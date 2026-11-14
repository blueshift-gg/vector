/**
 * Offline verification tests — NO validator. Per-scheme sign → verify
 * round trips, tamper detection, on-chain-acceptance parity for malleated
 * (high-S) secp256k1 signatures, and the cross-language digest pin shared
 * with `crates/core/tests/verify.rs`.
 */
import { describe, test, expect } from "vitest";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";

import {
  ADVANCE_DISCRIMINATOR,
  ED25519,
  EIP191,
  FALCON512,
  SECP256K1,
  advanceVectorDigest,
  ed25519Identity,
  eip191Identity,
  falcon512Keygen,
  mldsa44Keygen,
  createInitializeMlDsa44,
  INITIALIZE_DISCRIMINATOR,
  MLDSA44,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  findVectorPda,
  revocationDigest,
  secp256k1Identity,
  signAdvanceInstructionEd25519,
  signAdvanceInstructionEip191,
  signAdvanceInstructionFalcon512,
  signAdvanceInstructionMlDsa44,
  signAdvanceInstructionSecp256k1,
  signRevocationInstructionEd25519,
} from "../src/index.js";
import {
  IdentityMismatchError,
  MalformedSignatureError,
  SignatureVerificationError,
  verifyAdvanceSignature,
} from "../src/verify.js";

const NONCE = new Uint8Array(32).fill(0x01);
const SYSTEM_PROGRAM = new PublicKey("11111111111111111111111111111111");

const addr = (b: number) => new PublicKey(new Uint8Array(32).fill(b));
const meta = (b: number, isSigner: boolean, isWritable: boolean) => ({
  pubkey: addr(b),
  isSigner,
  isWritable,
});

/**
 * Deterministic pre/post instructions: the advance sits at index 1, so
 * every round trip below also exercises the non-zero sysvar index footer.
 * Byte-identical to `fixed_ix_lists` in `crates/core/tests/verify.rs`.
 */
function fixedIxLists() {
  const pre = new TransactionInstruction({
    programId: SYSTEM_PROGRAM,
    keys: [meta(0x11, true, true), meta(0x22, false, false)],
    data: Buffer.from([1, 2, 3, 4]),
  });
  const post = new TransactionInstruction({
    programId: SYSTEM_PROGRAM,
    keys: [meta(0x33, false, true), meta(0x44, false, false)],
    data: Buffer.from([9, 9]),
  });
  return { pre: [pre], post: [post] };
}

/**
 * Wire signature carried in a one-signer `advance` ix: the data after the
 * discriminator and the 8-byte `validUntil`.
 */
function sigOf(advanceIx: TransactionInstruction): Uint8Array {
  expect(advanceIx.data[0]).toBe(ADVANCE_DISCRIMINATOR);
  return new Uint8Array(advanceIx.data.subarray(1 + 8));
}

/** Negate `s` — the high-S malleated twin of a (noble-produced) low-S sig. */
function malleateHighS(compact: Uint8Array): Uint8Array {
  const sig = secp256k1.Signature.fromBytes(compact, "compact");
  return new secp256k1.Signature(sig.r, secp256k1.CURVE.n - sig.s).toBytes("compact");
}

// ── Round trips (advance NOT at index 0 — the footer regression case) ─

describe("sign → verify round trips", () => {
  test("ed25519 returns the digest (= next nonce)", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = ed25519Identity(key);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionEd25519(key, NONCE, pre, post);
    const digest = verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, NONCE, pre, post, sigOf(advance));

    const expected = advanceVectorDigest(ED25519, NONCE, pubkey, pre, post);
    expect(bytesToHex(digest)).toBe(bytesToHex(expected));
  });

  test("secp256k1 (64-byte compact, raw digest) + high-S twin", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = secp256k1Identity(key);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionSecp256k1(key, NONCE, pre, post);
    const wire = sigOf(advance);
    const digest = verifyAdvanceSignature({ scheme: SECP256K1, identity: pubkey }, NONCE, pre, post, wire);
    expect(digest.length).toBe(32);

    // On-chain `solana-secp256k1-ecdsa` accepts both s normalizations, so
    // the offline check must accept the malleated twin too.
    expect(() =>
      verifyAdvanceSignature({ scheme: SECP256K1, identity: pubkey }, NONCE, pre, post, malleateHighS(wire))
    ).not.toThrow();
  });

  test("eip191 (65-byte r||s||v, envelope, address recovery) + high-S twin", () => {
    const key = new Uint8Array(32).fill(0x43);
    const ethAddress = eip191Identity(key);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionEip191(key, NONCE, pre, post);
    const wire = sigOf(advance);
    const digest = verifyAdvanceSignature({ scheme: EIP191, identity: ethAddress }, NONCE, pre, post, wire);
    expect(digest.length).toBe(32);

    // High-S twin: the recovery id's parity bit flips with the negated s,
    // recovering the same key — what `sol_secp256k1_recover` does on-chain.
    const malleated = new Uint8Array(65);
    malleated.set(malleateHighS(wire.subarray(0, 64)));
    malleated[64] = wire[64] ^ 1;
    expect(() =>
      verifyAdvanceSignature({ scheme: EIP191, identity: ethAddress }, NONCE, pre, post, malleated)
    ).not.toThrow();
  });

  test("falcon512 (zero-padded wire signature, wire pubkey input)", () => {
    const keypair = falcon512Keygen(new Uint8Array(48).fill(0x54));
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionFalcon512(keypair, NONCE, pre, post);
    const signature = sigOf(advance);
    const digest = verifyAdvanceSignature({ scheme: FALCON512, identity: keypair.publicKey }, NONCE, pre, post, signature
    );
    expect(digest.length).toBe(32);

    // Same signature against a tampered nonce must fail.
    const badNonce = new Uint8Array(NONCE);
    badNonce[0] ^= 0x01;
    expect(() =>
      verifyAdvanceSignature({ scheme: FALCON512, identity: keypair.publicKey }, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);
  });

  test("mldsa44 (standard key as identity, empty context)", () => {
    const keypair = mldsa44Keygen(new Uint8Array(32).fill(0x44));
    expect(keypair.publicKey.length).toBe(MLDSA44.identityLen);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionMlDsa44(keypair, NONCE, pre, post);
    const signature = sigOf(advance);
    expect(signature.length).toBe(MLDSA44.signatureLen);
    const digest = verifyAdvanceSignature({ scheme: MLDSA44, identity: keypair.publicKey }, NONCE, pre, post, signature
    );
    expect(digest).toEqual(advanceVectorDigest(MLDSA44, NONCE, keypair.publicKey, pre, post));

    const badNonce = new Uint8Array(NONCE);
    badNonce[0] ^= 0x01;
    expect(() =>
      verifyAdvanceSignature({ scheme: MLDSA44, identity: keypair.publicKey }, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);
    const tampered = new Uint8Array(signature);
    tampered[100] ^= 0x01;
    expect(() =>
      verifyAdvanceSignature({ scheme: MLDSA44, identity: keypair.publicKey }, NONCE, pre, post, tampered)
    ).toThrow(SignatureVerificationError);

    // Registration is three initialize calls; only the first carries the key.
    const register = createInitializeMlDsa44(addr(0x33), keypair.publicKey);
    expect(register.length).toBe(3);
    expect(register[0].data.length).toBe(2 + MLDSA44.identityLen);
    for (const grow of register.slice(1)) {
      expect(Array.from(grow.data)).toEqual([INITIALIZE_DISCRIMINATOR]);
      expect(grow.keys).toEqual(register[0].keys);
    }

    // Shared with tests/mldsa44.rs: identity, PDA and digest.
    const publicKey = new Uint8Array(1312).fill(0x44);
    const [pda, bump] = findVectorPda(MLDSA44, publicKey);
    expect(pda.toString()).toBe("DSMGfPwdpxKeB7ai2vYrRSzTLPDTXKTFujjBMeGkKfMc");
    expect(bump).toBe(254);
    const passthrough = createPassthroughInstruction(MLDSA44, publicKey, [
      createWithdrawSubinstruction(MLDSA44, publicKey, addr(9), 1234n),
    ]);
    const pinned = advanceVectorDigest(
      MLDSA44, new Uint8Array(32).fill(255), publicKey, [], [passthrough]
    );
    expect(Buffer.from(pinned).toString("hex")).toBe(
      "f15dbead82e22b65227273d9a513ddb6ef718b79d5d37746e34dac35a422d35a"
    );
  });
});

// ── Tamper detection ─────────────────────────────────────────────────

describe("tamper detection", () => {
  const key = new Uint8Array(32).fill(0x42);
  const pubkey = ed25519Identity(key);
  const { pre, post } = fixedIxLists();
  const signature = sigOf(signAdvanceInstructionEd25519(key, NONCE, pre, post));

  test("any tampered committed byte fails verification", () => {
    // Instruction data.
    const a = fixedIxLists();
    a.pre[0].data[0] ^= 0x01;
    expect(() =>
      verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, NONCE, a.pre, a.post, signature)
    ).toThrow(SignatureVerificationError);

    // Account pubkey.
    const b = fixedIxLists();
    b.post[0].keys[0].pubkey = addr(0x55);
    expect(() =>
      verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, NONCE, b.pre, b.post, signature)
    ).toThrow(SignatureVerificationError);

    // Nonce.
    const badNonce = new Uint8Array(NONCE);
    badNonce[31] ^= 0x01;
    expect(() =>
      verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);

    // Identity (a different — still valid — pubkey).
    const other = ed25519Identity(new Uint8Array(32).fill(0x43));
    expect(() =>
      verifyAdvanceSignature({ scheme: ED25519, identity: other }, NONCE, pre, post, signature)
    ).toThrow(SignatureVerificationError);
  });
});

// ── EIP-191 recovery byte ────────────────────────────────────────────

describe("eip191 recovery byte", () => {
  const key = new Uint8Array(32).fill(0x43);
  const ethAddress = eip191Identity(key);
  const { pre, post } = fixedIxLists();
  const signature = sigOf(signAdvanceInstructionEip191(key, NONCE, pre, post));

  test("wallet 27/28 form is accepted, as on chain (v % 27)", () => {
    const legacy = new Uint8Array(signature);
    legacy[64] = signature[64] + 27; // what Ethereum tooling emits
    expect(() =>
      verifyAdvanceSignature({ scheme: EIP191, identity: ethAddress }, NONCE, pre, post, legacy)
    ).not.toThrow();
  });

  test("a recovery byte outside 0..=3 and 27..=30 is malformed", () => {
    const bad = new Uint8Array(signature);
    bad[64] = 4;
    expect(() =>
      verifyAdvanceSignature({ scheme: EIP191, identity: ethAddress }, NONCE, pre, post, bad)
    ).toThrow(MalformedSignatureError);
  });

  test("signature from a different key reports an identity mismatch", () => {
    const otherAddress = eip191Identity(new Uint8Array(32).fill(0x44));
    expect(() =>
      verifyAdvanceSignature({ scheme: EIP191, identity: otherAddress }, NONCE, pre, post, signature)
    ).toThrow(IdentityMismatchError);
  });
});

// ── Cross-language digest pin ────────────────────────────────────────

/**
 * Digest of the deterministic layout in `fixedIxLists` (ed25519 identity
 * from seed 0x42·32, nonce 0x01·32, no fee payer, advance at index 1).
 * `crates/core/tests/verify.rs` pins the SAME constant — if either
 * implementation drifts (hashing, sysvar serialization, flag promotion,
 * index footer), its half of the pin breaks.
 */
const PINNED_DIGEST_HEX =
  "c7a416250641b0799af333015a2b87923131f8cab638b3daafc277e808e74280";

describe("cross-language digest pin", () => {
  test("digest matches the constant pinned by the Rust suite", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = ed25519Identity(key);
    const { pre, post } = fixedIxLists();

    const digest = advanceVectorDigest(ED25519, NONCE, pubkey, pre, post);
    expect(bytesToHex(digest)).toBe(PINNED_DIGEST_HEX);

    // And the pinned digest is exactly what a signer commits to.
    const advance = signAdvanceInstructionEd25519(key, NONCE, pre, post);
    const verified = verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, NONCE, pre, post, sigOf(advance));
    expect(bytesToHex(verified)).toBe(PINNED_DIGEST_HEX);
  });
});

// ── Revocation (inert advance) ───────────────────────────────────────

/**
 * Revocation digest for (ed25519 identity from seed 0x42·32, nonce
 * 0x01·32): an inert advance, empty pre/post, no fee payer.
 * `crates/core/tests/verify.rs` pins the SAME constant — if either
 * implementation drifts, its half of the pin breaks.
 */
const PINNED_REVOCATION_DIGEST_HEX =
  "40ad59cf6f9853f02d2668e092573e6b7b8131cc0c335dd29a03747759b450cf";

describe("revocation (inert advance)", () => {
  test("round trip + cross-language pin", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = ed25519Identity(key);

    // A revocation is just an advance with empty pre/post, so it verifies
    // through the ordinary advance verifier with empty arrays.
    const revocation = signRevocationInstructionEd25519(key, NONCE);
    const digest = verifyAdvanceSignature({ scheme: ED25519, identity: pubkey }, NONCE, [], [], sigOf(revocation));

    expect(bytesToHex(digest)).toBe(bytesToHex(revocationDigest(ED25519, NONCE, pubkey)));
    expect(bytesToHex(digest)).toBe(PINNED_REVOCATION_DIGEST_HEX);
  });
});
