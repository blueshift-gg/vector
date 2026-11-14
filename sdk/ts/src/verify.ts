/**
 * Check `advance` signatures offline, the way the program will: for one
 * signer ({@link verifyAdvanceSignature}) or for every signer of an assembled
 * transaction ({@link verifyAdvanceTransaction}), vector accounts and nonce
 * accounts alike.
 */
import {
  PublicKey,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { falcon512 as nobleFalcon } from "@noble/post-quantum/falcon.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

import { bytesEqual, readU64LE, sha256, VALID_UNTIL_LEN } from "./bytes.js";
import { ADVANCE_DISCRIMINATOR, PROGRAM_ID, Scheme, findVectorPda, signedNonce } from "./scheme.js";
import {
  AdvanceSigner,
  NEVER_EXPIRES,
  advanceMessage,
  signedMessage,
  signerDigest,
  transactionMessage,
} from "./digest.js";
import { ED25519 } from "./schemes/ed25519.js";
import { EIP191, eip191EnvelopeHash } from "./schemes/eip191.js";
import { SECP256K1 } from "./schemes/secp256k1.js";
import { FALCON512 } from "./schemes/falcon512.js";
import { MLDSA44 } from "./schemes/mldsa44.js";

// ── Errors ───────────────────────────────────────────────────────────

/** Base class for every offline-verification failure. */
export class VerifyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The signature bytes are unusable before any curve math runs (wrong
 * length, out-of-range scalar, invalid recovery byte), or the instruction
 * data is not laid out as an `advance`'s.
 */
export class MalformedSignatureError extends VerifyError {}

/**
 * The key material and the identity disagree (wrong identity length, an
 * EIP-191 recovery yielding a different address), or the scheme has no
 * offline verifier.
 */
export class IdentityMismatchError extends VerifyError {}

/** The signature does not verify over the recomputed digest. */
export class SignatureVerificationError extends VerifyError {}

/** The transaction's `validUntil` slot is before the slot checked against. */
export class ExpiredError extends VerifyError {}

const SIGNATURE_INVALID =
  "signature does not verify over the recomputed advance digest — the " +
  "signed payload differs from this instruction layout, nonce, or identity";

// ── Helpers ──────────────────────────────────────────────────────────

/**
 * Strip the zero padding from a 666-byte Falcon signature. The compressed
 * stream never ends in a zero byte, so trailing zeros are padding.
 */
function trimFalconSignature(signature: Uint8Array): Uint8Array {
  let end = signature.length;
  while (end > 0 && signature[end - 1] === 0) end--;
  return signature.subarray(0, end);
}

/**
 * The nonce a signer signs over: its vector's own, or for a nonce account
 * {@link signedNonce} of the two. Pass the pair for a nonce account.
 */
export type SignedOver = Uint8Array | { account: Uint8Array; vector: Uint8Array };

function resolveNonce(nonce: SignedOver): Uint8Array {
  const resolved = nonce instanceof Uint8Array ? nonce : signedNonce(nonce.account, nonce.vector);
  if (resolved.length !== 32) {
    throw new MalformedSignatureError(`nonce must be 32 bytes, got ${resolved.length}`);
  }
  return resolved;
}

/** Check `signature` over `digest` with the scheme's verifier. */
function checkSignature(
  scheme: Scheme,
  identity: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array
): void {
  const verify = VERIFIERS[scheme.id];
  if (!verify) {
    throw new IdentityMismatchError("this scheme has no offline verifier");
  }
  if (identity.length !== scheme.identityLen) {
    throw new IdentityMismatchError(
      `identity must be ${scheme.identityLen} bytes, got ${identity.length}`
    );
  }
  if (signature.length !== scheme.signatureLen) {
    throw new MalformedSignatureError(
      `signature must be ${scheme.signatureLen} bytes, got ${signature.length}`
    );
  }
  let ok = false;
  try {
    ok = verify(identity, digest, signature);
  } catch (error) {
    if (error instanceof VerifyError) throw error;
  }
  if (!ok) throw new SignatureVerificationError(SIGNATURE_INVALID);
}

/**
 * Verify an advance signature of a one-signer advance: recompute the digest
 * and check `signature` over it with the scheme's verifier. Returns the
 * digest, which is the next nonce of the signer's nonce account, or of its
 * own.
 *
 * `nonce` is the one the signer signed over: the vector's own, or for a
 * signer with a `nonceAccount`, the pair `{ account, vector }` of the two
 * nonces. `validUntil` is the advance's expiry, which every signature
 * covers (default never expires). Pass `feePayer` when it is also an account of one of the instructions: the
 * runtime then marks it a writable signer there, and the digest covers that
 * flag. Winternitz and XMSS have no offline verifier. For an advance with
 * several signers use {@link verifyAdvanceTransaction}.
 */
export function verifyAdvanceSignature(
  signer: AdvanceSigner,
  nonce: SignedOver,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: PublicKey,
  validUntil?: bigint | number
): Uint8Array {
  const { scheme, identity } = signer;
  const signedOver = resolveNonce(nonce);
  const message = advanceMessage([signer], preInstructions, postInstructions, feePayer, validUntil);
  const digest = signerDigest(message, signedOver, findVectorPda(scheme, identity)[0], {
    nextKey: signer.nextKey,
  });
  checkSignature(scheme, identity, digest, signature);
  return digest;
}

// ── A whole transaction ──────────────────────────────────────────────

/** What a verifier knows of a vector account an `advance` lists. */
export type VectorState = {
  scheme: Scheme;
  /** The key the account was created with. */
  identity: Uint8Array;
  /** Its current nonce: the first 32 bytes of its account data. */
  nonce: Uint8Array;
};

/** What a verifier knows of a nonce account an `advance` lists. */
export type NonceAccountState = {
  address: PublicKey;
  /** Its current nonce: the first 32 bytes of its account data. */
  nonce: Uint8Array;
  /** The vector account it belongs to. */
  vector: PublicKey;
};

/** One signer of an assembled `advance`, checked. */
export type SignerResult = {
  /** The vector account. */
  vector: PublicKey;
  /** The nonce account it signed over, if any. */
  nonceAccount?: PublicKey;
  scheme: Scheme;
  /** The last slot the transaction may land in, the one every signer signed; {@link NEVER_EXPIRES} for none. */
  validUntil: bigint;
  nextKey: Uint8Array;
  signature: Uint8Array;
  /** What the signature is over (after {@link signedMessage}), and the next nonce. */
  digest: Uint8Array;
  /**
   * Whose nonce moves to `digest`: the nonce account's, or the vector's own.
   */
  moves: PublicKey;
  /** The signature verifies. */
  ok: boolean;
  /** Why it does not, if so. */
  error?: VerifyError;
};

export type VerifiedAdvance = {
  /** Where the `advance` is among the transaction's instructions. */
  advanceIndex: number;
  /** One per signer, in the order of the `advance`. */
  signers: SignerResult[];
  /** Every signer's signature verifies (and none is expired, given a `slot`). */
  ok: boolean;
};

/** The instructions of a transaction in any of the forms it may come in, and its fee payer. */
function readTransaction(
  transaction: VersionedTransaction | Transaction | Uint8Array | TransactionInstruction[]
): { instructions: TransactionInstruction[]; feePayer?: PublicKey } {
  if (Array.isArray(transaction)) return { instructions: transaction };
  if (transaction instanceof Transaction) {
    return { instructions: transaction.instructions, feePayer: transaction.feePayer ?? undefined };
  }
  const versioned =
    transaction instanceof Uint8Array ? VersionedTransaction.deserialize(transaction) : transaction;
  let decompiled: TransactionMessage;
  try {
    decompiled = TransactionMessage.decompile(versioned.message);
  } catch (error) {
    throw new MalformedSignatureError(
      `the transaction cannot be read offline (${(error as Error).message}): ` +
        "pass its instructions and fee payer"
    );
  }
  return { instructions: decompiled.instructions, feePayer: decompiled.payerKey };
}

/**
 * Verify every signature of an assembled transaction's first `advance`, as
 * the program would: it recomputes the message from the transaction as it
 * stands, then each signer's digest from the nonce its account holds. This is
 * what a relayer checks before it pays the fee.
 *
 * `transaction` is a V1 (or legacy) `VersionedTransaction`, a legacy
 * `Transaction`, the serialized bytes of either, or its instructions;
 * `feePayer` is read from a transaction, and otherwise given. A v0
 * transaction with address lookup tables cannot be read offline: pass its
 * instructions and fee payer. `vectors` and
 * `nonceAccounts` are what the `advance` lists, with their nonces as the
 * chain holds them (an account the `advance` lists that is in neither is an
 * error). A nonce account is read as belonging to the vector listed just
 * before it.
 *
 * Failures of one signature are in its result; a transaction that is not a
 * well-formed `advance` throws. Pass `slot` to also refuse an expired
 * `validUntil`. Winternitz and XMSS signers have no offline verifier and
 * come back not `ok`.
 */
export function verifyAdvanceTransaction(params: {
  transaction: VersionedTransaction | Transaction | Uint8Array | TransactionInstruction[];
  vectors: VectorState[];
  nonceAccounts?: NonceAccountState[];
  feePayer?: PublicKey;
  slot?: bigint | number;
}): VerifiedAdvance {
  const { vectors, nonceAccounts = [], slot } = params;
  const read = readTransaction(params.transaction);
  const instructions = read.instructions;
  const feePayer = params.feePayer ?? read.feePayer;

  const advanceIndex = instructions.findIndex(
    (ix) => ix.programId.equals(PROGRAM_ID) && ix.data[0] === ADVANCE_DISCRIMINATOR
  );
  if (advanceIndex < 0) throw new MalformedSignatureError("the transaction has no advance");
  const advance = instructions[advanceIndex];

  const vectorByAddress = new Map(
    vectors.map((vector) => [findVectorPda(vector.scheme, vector.identity)[0].toBase58(), vector])
  );
  const nonceByAddress = new Map(nonceAccounts.map((n) => [n.address.toBase58(), n]));
  // Each account's nonce as the chain advances through this instruction: an
  // account listed twice signs its second signature over the first's digest.
  const current = new Map<string, Uint8Array>();
  for (const [address, vector] of vectorByAddress) current.set(address, vector.nonce);
  for (const [address, nonce] of nonceByAddress) current.set(address, nonce.nonce);

  // Accounts: every vector, each optionally followed by its nonce account,
  // then the instructions sysvar.
  const listed = advance.keys.slice(0, -1);
  if (listed.length === 0) throw new MalformedSignatureError("the advance lists no signer");
  const entries: { vector: VectorState; vectorAddress: PublicKey; nonce?: NonceAccountState }[] = [];
  for (const { pubkey } of listed) {
    const address = pubkey.toBase58();
    const vector = vectorByAddress.get(address);
    if (vector) {
      entries.push({ vector, vectorAddress: pubkey });
      continue;
    }
    const nonce = nonceByAddress.get(address);
    const last = entries[entries.length - 1];
    if (!nonce || !last || last.nonce || !nonce.vector.equals(last.vectorAddress)) {
      throw new MalformedSignatureError(
        `the advance lists ${address}, which is neither a known vector account nor a ` +
          "nonce account of the vector before it"
      );
    }
    last.nonce = nonce;
  }

  const message = transactionMessage(instructions, advanceIndex, feePayer);
  let data = advance.data.subarray(1);
  const take = (length: number): Uint8Array => {
    if (data.length < length) {
      throw new MalformedSignatureError("the advance's data ends before its last signature");
    }
    const bytes = data.subarray(0, length);
    data = data.subarray(length);
    return bytes;
  };

  // One expiry for the advance, which the message covers.
  const validUntil = readU64LE(take(VALID_UNTIL_LEN), 0);

  const signers = entries.map(({ vector, vectorAddress, nonce }): SignerResult => {
    const { scheme, identity } = vector;
    const nextKey = take(scheme.nextKeyLen);
    const signature = take(scheme.signatureLen);

    const moves = nonce ? nonce.address : vectorAddress;
    const signedOver = nonce
      ? signedNonce(current.get(moves.toBase58())!, current.get(vectorAddress.toBase58())!)
      : current.get(vectorAddress.toBase58())!;
    const digest = signerDigest(message, signedOver, vectorAddress, { nextKey });
    current.set(moves.toBase58(), digest);

    const result: SignerResult = {
      vector: vectorAddress,
      nonceAccount: nonce?.address,
      scheme,
      validUntil,
      nextKey,
      signature,
      digest,
      moves,
      ok: true,
    };
    try {
      if (slot !== undefined && BigInt(slot) > validUntil) {
        throw new ExpiredError(`the transaction is valid until slot ${validUntil}, past ${slot}`);
      }
      checkSignature(scheme, identity, digest, signature);
    } catch (error) {
      if (!(error instanceof VerifyError)) throw error;
      result.ok = false;
      result.error = error;
    }
    return result;
  });
  if (data.length !== 0) {
    throw new MalformedSignatureError(`the advance's data has ${data.length} bytes after its last signature`);
  }
  return { advanceIndex, signers, ok: signers.every((signer) => signer.ok) };
}

// ── One check per scheme ─────────────────────────────────────────────

/**
 * One check per scheme, by scheme byte, over `digest`: each signs the
 * `"vector:" || digest` of {@link signedMessage}. The lengths are already
 * checked.
 */
const VERIFIERS: Record<
  number,
  (identity: Uint8Array, digest: Uint8Array, signature: Uint8Array) => boolean
> = {
  [ED25519.id]: (identity, digest, signature) =>
    ed25519.verify(signature, signedMessage(digest), identity),
  // A high-S signature is accepted, as it is on chain.
  [SECP256K1.id]: (identity, digest, signature) =>
    secp256k1.verify(signature, sha256(signedMessage(digest)), identity, { lowS: false }),
  [EIP191.id]: verifyEip191,
  [FALCON512.id]: (identity, digest, signature) =>
    nobleFalcon.verify(trimFalconSignature(signature), signedMessage(digest), identity),
  // The empty context, as on chain.
  [MLDSA44.id]: (identity, digest, signature) =>
    ml_dsa44.verify(signature, signedMessage(digest), identity),
};

/**
 * Recover the signer of the EIP-191 envelope and compare it to the address.
 * `v` is 0 or 1, or as wallets return it 27 or 28: the program takes it
 * modulo 27.
 */
function verifyEip191(
  ethAddress: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array
): boolean {
  const v = signature[64] % 27;
  if (v > 3) {
    throw new MalformedSignatureError(
      `eip191: recovery byte ${signature[64]} is not a valid v (expected 0..=3, or 27..=30)`
    );
  }
  const recovered = secp256k1.Signature.fromBytes(signature.subarray(0, 64), "compact")
    .addRecoveryBit(v)
    .recoverPublicKey(eip191EnvelopeHash(digest))
    .toBytes(false);
  if (!bytesEqual(keccak_256(recovered.subarray(1)).subarray(12), ethAddress)) {
    throw new IdentityMismatchError(
      "eip191: recovered Ethereum address does not match the identity"
    );
  }
  return true;
}
