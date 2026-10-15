/** Check an `advance` signature offline, the way the program will. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { falcon512 as nobleFalcon } from "@noble/post-quantum/falcon.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

import { Scheme } from "./scheme.js";
import { advanceVectorDigest } from "./digest.js";
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
 * length, out-of-range scalar, invalid recovery byte).
 */
export class MalformedSignatureError extends VerifyError {}

/**
 * The key material and the identity disagree (wrong identity length, an
 * EIP-191 recovery yielding a different address).
 */
export class IdentityMismatchError extends VerifyError {}

/** The signature does not verify over the recomputed digest. */
export class SignatureVerificationError extends VerifyError {}

const SIGNATURE_INVALID =
  "signature does not verify over the recomputed advance digest — the " +
  "signed payload differs from this instruction layout, nonce, or identity";

// ── Helpers ──────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Turn Ethereum's 27/28 recovery byte into the 0/1 the program requires. Call
 * it when packaging a signature from Ethereum tooling into an advance; {@link
 * verifyAdvanceSignature} rejects 27/28, as the program does.
 */
export function normalizeEip191RecoveryByte(v: number): number {
  if (v >= 0 && v <= 3) return v;
  if (v === 27 || v === 28) return v - 27;
  throw new MalformedSignatureError(
    `eip191: recovery byte ${v} is not a valid v (expected 0/1, or the Ethereum legacy 27/28)`
  );
}

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
 * Verify an advance signature: recompute the digest and check `signature`
 * over it with the scheme's verifier. Returns the digest, which is the
 * account's next nonce.
 *
 * Pass `feePayer` when it is also an account of one of the instructions: the
 * runtime then marks it a writable signer there, and the digest covers that
 * flag. Winternitz and XMSS have no offline verifier.
 */
export function verifyAdvanceSignature(
  scheme: Scheme,
  identity: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: Address
): Uint8Array {
  const verify = VERIFIERS[scheme.id];
  if (!verify) {
    throw new IdentityMismatchError("this scheme has no offline verifier");
  }
  if (nonce.length !== 32) {
    throw new MalformedSignatureError(`nonce must be 32 bytes, got ${nonce.length}`);
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

  const digest = advanceVectorDigest(
    scheme, nonce, identity, preInstructions, postInstructions, feePayer
  );
  let ok = false;
  try {
    ok = verify(identity, digest, signature);
  } catch (error) {
    if (error instanceof VerifyError) throw error;
  }
  if (!ok) throw new SignatureVerificationError(SIGNATURE_INVALID);
  return digest;
}

/** One check per scheme, by scheme byte. The lengths are already checked. */
const VERIFIERS: Record<
  number,
  (identity: Uint8Array, digest: Uint8Array, signature: Uint8Array) => boolean
> = {
  [ED25519.id]: (identity, digest, signature) =>
    ed25519.verify(signature, digest, identity),
  // A high-S signature is accepted, as it is on chain.
  [SECP256K1.id]: (identity, digest, signature) =>
    secp256k1.verify(signature, digest, identity, { lowS: false }),
  [EIP191.id]: verifyEip191,
  [FALCON512.id]: (identity, digest, signature) =>
    nobleFalcon.verify(trimFalconSignature(signature), digest, identity),
  // The empty context, as on chain.
  [MLDSA44.id]: (identity, digest, signature) =>
    ml_dsa44.verify(signature, digest, identity),
};

/**
 * Recover the signer of the EIP-191 envelope and compare it to the address.
 * `v` is the raw recovery id; Ethereum's 27/28 form is rejected, as it is on
 * chain. See {@link normalizeEip191RecoveryByte}.
 */
function verifyEip191(
  ethAddress: Uint8Array,
  digest: Uint8Array,
  signature: Uint8Array
): boolean {
  const v = signature[64];
  if (v === 27 || v === 28) {
    throw new MalformedSignatureError(
      `eip191: recovery byte is ${v} (Ethereum legacy 27/28 form); the ` +
        "on-chain program requires the raw 0/1 form — subtract 27 when " +
        "assembling the advance instruction (see normalizeEip191RecoveryByte)"
    );
  }
  if (v > 3) {
    throw new MalformedSignatureError(
      `eip191: recovery byte ${v} is not a valid v (expected 0..=3)`
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
