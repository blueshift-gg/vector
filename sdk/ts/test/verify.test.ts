/**
 * Offline verification tests — NO validator. Per-scheme sign → verify
 * round trips, tamper detection, on-chain-acceptance parity for malleated
 * (high-S) secp256k1 signatures, and the cross-language digest pin shared
 * with `crates/core/tests/verify.rs`.
 */
import { describe, test, expect } from "vitest";
import { Address, TransactionInstruction } from "@solana/web3.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";

import {
  ADVANCE_DISCRIMINATOR,
  ED25519,
  advanceVectorDigest,
  ed25519Identity,
  eip191Identity,
  falcon512Keygen,
  hawk512Keygen,
  secp256k1Identity,
  signAdvanceInstructionEd25519,
  signAdvanceInstructionEip191,
  signAdvanceInstructionFalcon512,
  signAdvanceInstructionHawk512,
  signAdvanceInstructionSecp256k1,
} from "../src/index.js";
import {
  IdentityMismatchError,
  MalformedSignatureError,
  SignatureVerificationError,
  normalizeEip191RecoveryByte,
  verifyAdvanceSignatureEd25519,
  verifyAdvanceSignatureEip191,
  verifyAdvanceSignatureFalcon512,
  verifyAdvanceSignatureHawk512,
  verifyAdvanceSignatureSecp256k1,
} from "../src/verify.js";

const NONCE = new Uint8Array(32).fill(0x01);
const SYSTEM_PROGRAM = new Address("11111111111111111111111111111111");

const addr = (b: number) => new Address(new Uint8Array(32).fill(b));
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

/** Wire signature carried in an `advance` ix: data after the discriminator. */
function sigOf(advanceIx: TransactionInstruction): Uint8Array {
  expect(advanceIx.data[0]).toBe(ADVANCE_DISCRIMINATOR);
  return new Uint8Array(advanceIx.data.subarray(1));
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
    const digest = verifyAdvanceSignatureEd25519(pubkey, NONCE, pre, post, sigOf(advance));

    const expected = advanceVectorDigest(ED25519, NONCE, pubkey, pre, post);
    expect(bytesToHex(digest)).toBe(bytesToHex(expected));
  });

  test("secp256k1 (64-byte compact, raw digest) + high-S twin", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = secp256k1Identity(key);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionSecp256k1(key, NONCE, pre, post);
    const wire = sigOf(advance);
    const digest = verifyAdvanceSignatureSecp256k1(pubkey, NONCE, pre, post, wire);
    expect(digest.length).toBe(32);

    // On-chain `solana-secp256k1-ecdsa` accepts both s normalizations, so
    // the offline check must accept the malleated twin too.
    expect(() =>
      verifyAdvanceSignatureSecp256k1(pubkey, NONCE, pre, post, malleateHighS(wire))
    ).not.toThrow();
  });

  test("eip191 (65-byte r||s||v, envelope, address recovery) + high-S twin", () => {
    const key = new Uint8Array(32).fill(0x43);
    const ethAddress = eip191Identity(key);
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionEip191(key, NONCE, pre, post);
    const wire = sigOf(advance);
    const digest = verifyAdvanceSignatureEip191(ethAddress, NONCE, pre, post, wire);
    expect(digest.length).toBe(32);

    // High-S twin: the recovery id's parity bit flips with the negated s,
    // recovering the same key — what `sol_secp256k1_recover` does on-chain.
    const malleated = new Uint8Array(65);
    malleated.set(malleateHighS(wire.subarray(0, 64)));
    malleated[64] = wire[64] ^ 1;
    expect(() =>
      verifyAdvanceSignatureEip191(ethAddress, NONCE, pre, post, malleated)
    ).not.toThrow();
  });

  test("falcon512 (zero-padded wire signature, wire pubkey input)", () => {
    const keypair = falcon512Keygen(new Uint8Array(48).fill(0x54));
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionFalcon512(keypair, NONCE, pre, post);
    const signature = sigOf(advance);
    const digest = verifyAdvanceSignatureFalcon512(
      keypair.publicKey, NONCE, pre, post, signature
    );
    expect(digest.length).toBe(32);

    // Same signature against a tampered nonce must fail.
    const badNonce = new Uint8Array(NONCE);
    badNonce[0] ^= 0x01;
    expect(() =>
      verifyAdvanceSignatureFalcon512(keypair.publicKey, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);
  });

  test("hawk512 (555-byte wire signature, wire pubkey input)", () => {
    const keypair = hawk512Keygen(new Uint8Array(32).fill(0x55));
    const { pre, post } = fixedIxLists();

    const advance = signAdvanceInstructionHawk512(keypair, NONCE, pre, post);
    const signature = sigOf(advance);
    const digest = verifyAdvanceSignatureHawk512(
      keypair.publicKey, NONCE, pre, post, signature
    );
    expect(digest.length).toBe(32);

    const badNonce = new Uint8Array(NONCE);
    badNonce[0] ^= 0x01;
    expect(() =>
      verifyAdvanceSignatureHawk512(keypair.publicKey, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);
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
      verifyAdvanceSignatureEd25519(pubkey, NONCE, a.pre, a.post, signature)
    ).toThrow(SignatureVerificationError);

    // Account pubkey.
    const b = fixedIxLists();
    b.post[0].keys[0].pubkey = addr(0x55);
    expect(() =>
      verifyAdvanceSignatureEd25519(pubkey, NONCE, b.pre, b.post, signature)
    ).toThrow(SignatureVerificationError);

    // Nonce.
    const badNonce = new Uint8Array(NONCE);
    badNonce[31] ^= 0x01;
    expect(() =>
      verifyAdvanceSignatureEd25519(pubkey, badNonce, pre, post, signature)
    ).toThrow(SignatureVerificationError);

    // Identity (a different — still valid — pubkey).
    const other = ed25519Identity(new Uint8Array(32).fill(0x43));
    expect(() =>
      verifyAdvanceSignatureEd25519(other, NONCE, pre, post, signature)
    ).toThrow(SignatureVerificationError);
  });
});

// ── EIP-191 recovery byte ────────────────────────────────────────────

describe("eip191 recovery byte", () => {
  const key = new Uint8Array(32).fill(0x43);
  const ethAddress = eip191Identity(key);
  const { pre, post } = fixedIxLists();
  const signature = sigOf(signAdvanceInstructionEip191(key, NONCE, pre, post));

  test("legacy 27/28 form is rejected with subtract-27 guidance", () => {
    const legacy = new Uint8Array(signature);
    legacy[64] = signature[64] + 27; // what Ethereum tooling emits
    expect(() =>
      verifyAdvanceSignatureEip191(ethAddress, NONCE, pre, post, legacy)
    ).toThrow(MalformedSignatureError);
    expect(() =>
      verifyAdvanceSignatureEip191(ethAddress, NONCE, pre, post, legacy)
    ).toThrow(/27\/28.*subtract 27/s);
  });

  test("normalizeEip191RecoveryByte converts at assembly time", () => {
    expect(normalizeEip191RecoveryByte(27)).toBe(0);
    expect(normalizeEip191RecoveryByte(28)).toBe(1);
    expect(normalizeEip191RecoveryByte(signature[64])).toBe(signature[64]);
    expect(() => normalizeEip191RecoveryByte(29)).toThrow(MalformedSignatureError);

    const normalized = new Uint8Array(signature);
    normalized[64] = normalizeEip191RecoveryByte(signature[64] + 27);
    expect(() =>
      verifyAdvanceSignatureEip191(ethAddress, NONCE, pre, post, normalized)
    ).not.toThrow();
  });

  test("signature from a different key reports an identity mismatch", () => {
    const otherAddress = eip191Identity(new Uint8Array(32).fill(0x44));
    expect(() =>
      verifyAdvanceSignatureEip191(otherAddress, NONCE, pre, post, signature)
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
  "fb561cf20b01b2940889b1652f732ea100256e74f10675a3e169b1895b0a9e4f";

describe("cross-language digest pin", () => {
  test("digest matches the constant pinned by the Rust suite", () => {
    const key = new Uint8Array(32).fill(0x42);
    const pubkey = ed25519Identity(key);
    const { pre, post } = fixedIxLists();

    const digest = advanceVectorDigest(ED25519, NONCE, pubkey, pre, post);
    expect(bytesToHex(digest)).toBe(PINNED_DIGEST_HEX);

    // And the pinned digest is exactly what a signer commits to.
    const advance = signAdvanceInstructionEd25519(key, NONCE, pre, post);
    const verified = verifyAdvanceSignatureEd25519(pubkey, NONCE, pre, post, sigOf(advance));
    expect(bytesToHex(verified)).toBe(PINNED_DIGEST_HEX);
  });
});
