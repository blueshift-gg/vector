/**
 * Offline verification of whole transactions — NO validator: several signers
 * in one `advance`, signers over nonce accounts, `validUntil`, and a
 * transaction round-tripped through its wire format.
 */
import { describe, expect, test } from "vitest";
import { Keypair, PublicKey, SystemProgram, Transaction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1";

import {
  AdvanceSigner,
  ED25519,
  NEVER_EXPIRES,
  SECP256K1,
  advanceMessage,
  advanceVectorDigest,
  createMultiAdvanceInstruction,
  createMultiPassthroughInstruction,
  createWithdrawSubinstruction,
  ed25519Identity,
  findVectorPda,
  secp256k1Identity,
  signAdvanceInstructionEd25519,
  signedMessage,
  signedNonce,
  signerDigest,
  verifyAdvanceSignature,
  verifyAdvanceTransaction,
  type NonceAccountState,
  type VectorState,
} from "../src/index.js";
import { sha256 } from "../src/bytes.js";

const ED_KEY = new Uint8Array(32).fill(0x42);
const SECP_KEY = new Uint8Array(32).fill(0x43);
const ED_IDENTITY = ed25519Identity(ED_KEY);
const SECP_IDENTITY = secp256k1Identity(SECP_KEY);
const [ED_VECTOR] = findVectorPda(ED25519, ED_IDENTITY);
const [SECP_VECTOR] = findVectorPda(SECP256K1, SECP_IDENTITY);
const RECEIVER = new PublicKey(new Uint8Array(32).fill(9));
const NONCE_ACCOUNT = new PublicKey(new Uint8Array(32).fill(0x70));

const ED_NONCE = new Uint8Array(32).fill(1);
const SECP_NONCE = new Uint8Array(32).fill(2);
const NONCE_ACCOUNT_NONCE = new Uint8Array(32).fill(3);

const vectors: VectorState[] = [
  { scheme: ED25519, identity: ED_IDENTITY, nonce: ED_NONCE },
  { scheme: SECP256K1, identity: SECP_IDENTITY, nonce: SECP_NONCE },
];
const nonceAccounts: NonceAccountState[] = [
  { address: NONCE_ACCOUNT, nonce: NONCE_ACCOUNT_NONCE, vector: ED_VECTOR },
];

/** What each scheme's key signs for a digest, as the program verifies it. */
const signers = {
  ed25519: (digest: Uint8Array) => ed25519.sign(signedMessage(digest), ED_KEY),
  secp256k1: (digest: Uint8Array) =>
    secp256k1.sign(sha256(signedMessage(digest)), SECP_KEY).toBytes("compact"),
};

/** A passthrough acting as both vectors, then a withdraw each. */
function post() {
  return [
    createMultiPassthroughInstruction(
      [
        { scheme: ED25519, identity: ED_IDENTITY },
        { scheme: SECP256K1, identity: SECP_IDENTITY },
      ],
      [
        createWithdrawSubinstruction(ED25519, ED_IDENTITY, RECEIVER, 1n),
        createWithdrawSubinstruction(SECP256K1, SECP_IDENTITY, RECEIVER, 2n),
      ]
    ),
  ];
}

/**
 * An advance of an Ed25519 and a secp256k1 signer, signed. `edNonce` is what
 * the Ed25519 signer signs over, the nonce account's if it lists one.
 */
function twoSigners(options: { nonceAccount?: PublicKey; validUntil?: bigint; edNonce?: Uint8Array } = {}) {
  const listed: AdvanceSigner[] = [
    {
      scheme: ED25519,
      identity: ED_IDENTITY,
      nonceAccount: options.nonceAccount,
    },
    { scheme: SECP256K1, identity: SECP_IDENTITY },
  ];
  const instructions = post();
  const message = advanceMessage(listed, [], instructions, undefined, options.validUntil);
  const edNonce =
    options.edNonce ?? (options.nonceAccount ? signedNonce(NONCE_ACCOUNT_NONCE, ED_NONCE) : ED_NONCE);
  const edDigest = signerDigest(message, edNonce, ED_VECTOR);
  const secpDigest = signerDigest(message, SECP_NONCE, SECP_VECTOR);
  const advance = createMultiAdvanceInstruction(
    [
      { ...listed[0], signature: signers.ed25519(edDigest) },
      { ...listed[1], signature: signers.secp256k1(secpDigest) },
    ],
    options.validUntil
  );
  return { transaction: [advance, ...instructions], edDigest, secpDigest, instructions };
}

describe("an advance of several signers", () => {
  test("every signature verifies, and each result is its signer's digest", () => {
    const { transaction, edDigest, secpDigest } = twoSigners();
    const result = verifyAdvanceTransaction({ transaction, vectors });
    expect(result.ok).toBe(true);
    expect(result.advanceIndex).toBe(0);
    expect(result.signers.map((s) => s.vector.toBase58())).toEqual([
      ED_VECTOR.toBase58(),
      SECP_VECTOR.toBase58(),
    ]);
    expect(result.signers[0].digest).toEqual(edDigest);
    expect(result.signers[1].digest).toEqual(secpDigest);
    expect(result.signers[0].moves.equals(ED_VECTOR)).toBe(true);
    expect(result.signers.every((s) => s.validUntil === NEVER_EXPIRES)).toBe(true);
  });

  test("a change to the transaction fails every signer", () => {
    const { transaction } = twoSigners();
    // The last byte of the passthrough's data is in the withdraw's amount.
    const changed = transaction[1].data.slice();
    changed[changed.length - 1] ^= 1;
    transaction[1].data = changed;
    const result = verifyAdvanceTransaction({ transaction, vectors });
    expect(result.ok).toBe(false);
    expect(result.signers.map((s) => s.ok)).toEqual([false, false]);
  });

  test("one wrong signature is that signer's alone", () => {
    const { transaction } = twoSigners();
    const nonces = vectors.map((v, i) => (i === 1 ? { ...v, nonce: new Uint8Array(32).fill(9) } : v));
    const result = verifyAdvanceTransaction({ transaction, vectors: nonces });
    expect(result.signers.map((s) => s.ok)).toEqual([true, false]);
    expect(result.signers[1].error?.name).toBe("SignatureVerificationError");
    expect(result.ok).toBe(false);
  });

  test("an account listed twice signs its second over the first's digest", () => {
    const listed: AdvanceSigner[] = [
      { scheme: ED25519, identity: ED_IDENTITY },
      { scheme: ED25519, identity: ED_IDENTITY },
    ];
    const instructions = post().slice(0, 0);
    const message = advanceMessage(listed, [], instructions);
    const first = signerDigest(message, ED_NONCE, ED_VECTOR);
    const second = signerDigest(message, first, ED_VECTOR);
    const advance = createMultiAdvanceInstruction([
      { ...listed[0], signature: signers.ed25519(first) },
      { ...listed[1], signature: signers.ed25519(second) },
    ]);
    const result = verifyAdvanceTransaction({ transaction: [advance], vectors });
    expect(result.ok).toBe(true);
    expect(result.signers[1].digest).toEqual(second);
  });

  test("a transaction with no advance, or data left over, is malformed", () => {
    expect(() => verifyAdvanceTransaction({ transaction: post(), vectors })).toThrow(/no advance/);
    const { transaction } = twoSigners();
    transaction[0].data = Uint8Array.of(...transaction[0].data, 0);
    expect(() => verifyAdvanceTransaction({ transaction, vectors })).toThrow(/after its last/);
    expect(() =>
      verifyAdvanceTransaction({ transaction: twoSigners().transaction, vectors: vectors.slice(0, 1) })
    ).toThrow(/neither a known vector/);
  });
});

describe("a signer over a nonce account", () => {
  test("signs over the nonce account's nonce and the vector's, and moves only the former", () => {
    const { transaction, edDigest } = twoSigners({ nonceAccount: NONCE_ACCOUNT });
    const result = verifyAdvanceTransaction({ transaction, vectors, nonceAccounts });
    expect(result.ok).toBe(true);
    expect(result.signers[0].nonceAccount?.equals(NONCE_ACCOUNT)).toBe(true);
    expect(result.signers[0].moves.equals(NONCE_ACCOUNT)).toBe(true);
    expect(result.signers[0].digest).toEqual(edDigest);
    expect(result.signers[1].moves.equals(SECP_VECTOR)).toBe(true);
  });

  test("a signature over the vector's own nonce is not one over the nonce account's", () => {
    const { transaction } = twoSigners({ nonceAccount: NONCE_ACCOUNT, edNonce: ED_NONCE });
    const result = verifyAdvanceTransaction({ transaction, vectors, nonceAccounts });
    expect(result.signers.map((s) => s.ok)).toEqual([false, true]);
  });

  test("moving the vector's own nonce voids it", () => {
    const { transaction } = twoSigners({ nonceAccount: NONCE_ACCOUNT });
    const moved = vectors.map((v, i) => (i === 0 ? { ...v, nonce: new Uint8Array(32).fill(8) } : v));
    expect(verifyAdvanceTransaction({ transaction, vectors: moved, nonceAccounts }).signers[0].ok).toBe(false);
  });

  test("a nonce account of another vector is refused", () => {
    const { transaction } = twoSigners({ nonceAccount: NONCE_ACCOUNT });
    expect(() =>
      verifyAdvanceTransaction({
        transaction,
        vectors,
        nonceAccounts: [{ ...nonceAccounts[0], vector: SECP_VECTOR }],
      })
    ).toThrow(/neither a known vector/);
  });

  test("verifyAdvanceSignature takes the pair of nonces for one signer", () => {
    const signer: AdvanceSigner = { scheme: ED25519, identity: ED_IDENTITY, nonceAccount: NONCE_ACCOUNT };
    const instructions = post().slice(0, 0);
    const message = advanceMessage([signer], [], instructions);
    const digest = signerDigest(message, signedNonce(NONCE_ACCOUNT_NONCE, ED_NONCE), ED_VECTOR);
    const signature = signers.ed25519(digest);
    const nonce = { account: NONCE_ACCOUNT_NONCE, vector: ED_NONCE };
    expect(verifyAdvanceSignature(signer, nonce, [], instructions, signature)).toEqual(digest);
    expect(() =>
      verifyAdvanceSignature(signer, ED_NONCE, [], instructions, signature)
    ).toThrow(/does not verify/);
  });
});

describe("validUntil", () => {
  test("is in the digest and in the data", () => {
    const base = advanceVectorDigest(ED25519, ED_NONCE, ED_IDENTITY, [], []);
    const never = advanceVectorDigest(ED25519, ED_NONCE, ED_IDENTITY, [], [], undefined, NEVER_EXPIRES);
    const until = advanceVectorDigest(ED25519, ED_NONCE, ED_IDENTITY, [], [], undefined, 1000);
    expect(never).toEqual(base);
    expect(until).not.toEqual(base);

    const advance = signAdvanceInstructionEd25519(ED_KEY, ED_NONCE, [], [], undefined, 1000);
    expect(Array.from(advance.data.subarray(1, 9))).toEqual([0xe8, 3, 0, 0, 0, 0, 0, 0]);
    expect(() => signAdvanceInstructionEd25519(ED_KEY, ED_NONCE, [], [], undefined, -1)).toThrow();
    expect(() => signAdvanceInstructionEd25519(ED_KEY, ED_NONCE, [], [], undefined, 1n << 64n)).toThrow();
  });

  test("the transaction expires after its slot, for every signer, and no one can extend it", () => {
    const { transaction } = twoSigners({ validUntil: 100n });
    expect(verifyAdvanceTransaction({ transaction, vectors, slot: 100 }).ok).toBe(true);
    const late = verifyAdvanceTransaction({ transaction, vectors, slot: 101 });
    expect(late.signers.map((s) => s.ok)).toEqual([false, false]);
    expect(late.signers[0].error?.name).toBe("ExpiredError");
    expect(late.signers.every((s) => s.validUntil === 100n)).toBe(true);

    // The data's `validUntil` is in the message every signer signed: raising
    // it voids both signatures, not one.
    const raised = transaction[0].data.slice();
    raised[1] = 0xff;
    transaction[0].data = raised;
    expect(verifyAdvanceTransaction({ transaction, vectors }).signers.map((s) => s.ok)).toEqual([
      false,
      false,
    ]);
  });
});

describe("an assembled Transaction", () => {
  test("verifies from its wire bytes, fee payer and all", async () => {
    const feePayer = await Keypair.generate();
    const listed: AdvanceSigner[] = [{ scheme: ED25519, identity: ED_IDENTITY }];
    // The fee payer is also an account of an instruction: its flags are in the digest.
    const transfer = SystemProgram.transfer({
      fromPubkey: feePayer.publicKey,
      toPubkey: RECEIVER,
      lamports: 5,
    });
    const instructions = [...post().slice(0, 0), transfer];
    const message = advanceMessage(listed, [], instructions, feePayer.publicKey);
    const digest = signerDigest(message, ED_NONCE, ED_VECTOR);
    const advance = createMultiAdvanceInstruction([{ ...listed[0], signature: signers.ed25519(digest) }]);

    const tx = new Transaction({ feePayer: feePayer.publicKey }).add(advance, ...instructions);
    tx.recentBlockhash = new PublicKey(new Uint8Array(32).fill(5)).toBase58() as never;
    const bytes = await tx.serialize({ requireAllSignatures: false, verifySignatures: false });

    expect(verifyAdvanceTransaction({ transaction: bytes, vectors }).ok).toBe(true);
    expect(verifyAdvanceTransaction({ transaction: tx, vectors }).ok).toBe(true);
    // Instructions alone, with no fee payer given, have the same flags here:
    // the transfer already names the fee payer as a writable signer.
    expect(verifyAdvanceTransaction({ transaction: tx.instructions, vectors }).ok).toBe(true);
  });
});
