/**
 * Offline verification of `advance` signatures. Each function recomputes
 * the canonical digest via {@link advanceVectorDigest} and checks the
 * signature the way the on-chain program will, so a PASS here means the
 * transaction will verify on-chain against the same nonce. On success each
 * function returns the digest — which **is** the account's next nonce, so
 * chains of dependent transactions can be pre-signed by feeding each digest
 * into the next signing call.
 *
 * `feePayer` participates in **message-level flag promotion only**: the
 * live sysvar the on-chain program hashes carries message-level account
 * flags, and the fee payer is always a writable signer at the message
 * level. The digest is therefore independent of the fee payer **unless**
 * its key appears among the committed instructions' accounts, in which
 * case promotion folds it in and the signature is bound to that fee payer.
 *
 * Mirrors `crates/core/src/verify.rs`.
 */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { falcon512 as nobleFalcon } from "@noble/post-quantum/falcon.js";

import { Scheme, sha256, FALCON_PUBKEY_LEN } from "./scheme.js";
import { advanceVectorDigest } from "./digest.js";
import { ED25519 } from "./schemes/ed25519.js";
import { EIP191, eip191EnvelopeHash } from "./schemes/eip191.js";
import { SECP256K1 } from "./schemes/secp256k1.js";
import { FALCON512 } from "./schemes/falcon512.js";

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

/** Length gates shared by every scheme; throws before any crypto runs. */
function checkInputs(
  scheme: string,
  nonce: Uint8Array,
  identity: Uint8Array,
  identityLen: number,
  signature: Uint8Array,
  signatureLen: number
): void {
  if (nonce.length !== 32) {
    throw new MalformedSignatureError(
      `${scheme}: nonce must be 32 bytes, got ${nonce.length}`
    );
  }
  if (identity.length !== identityLen) {
    throw new IdentityMismatchError(
      `${scheme}: identity/pubkey must be ${identityLen} bytes, got ${identity.length}`
    );
  }
  if (signature.length !== signatureLen) {
    throw new MalformedSignatureError(
      `${scheme}: signature must be ${signatureLen} bytes, got ${signature.length}`
    );
  }
}

/**
 * Normalize an EIP-191 recovery byte from the Ethereum legacy 27/28
 * convention to the 0/1 form the on-chain program requires (it passes `v`
 * straight to `sol_secp256k1_recover`, which rejects recovery ids > 3).
 *
 * Call this at **assembly time**, when packaging a signature produced by
 * Ethereum tooling (`personal_sign`, HSMs, wallets) into an advance
 * instruction. {@link verifyAdvanceSignatureEip191} deliberately does NOT
 * accept 27/28 — an artifact carrying a legacy recovery byte would verify
 * offline but fail on-chain.
 */
export function normalizeEip191RecoveryByte(v: number): number {
  if (v >= 0 && v <= 3) return v;
  if (v === 27 || v === 28) return v - 27;
  throw new MalformedSignatureError(
    `eip191: recovery byte ${v} is not a valid v (expected 0/1, or the Ethereum legacy 27/28)`
  );
}

/**
 * Strip the zero padding from a 666-byte Falcon wire signature. The PQClean
 * compressed stream always ends with a coefficient's unary terminator bit,
 * so the final byte of the real stream is never `0x00` — trailing zero
 * bytes are unambiguously wire padding.
 */
function trimFalconSignature(signature: Uint8Array): Uint8Array {
  let end = signature.length;
  while (end > 0 && signature[end - 1] === 0) end--;
  return signature.subarray(0, end);
}

/** Shared tail: recompute the digest, run `verify`, map false → throw. */
function checkedDigest(
  name: string,
  scheme: Scheme,
  identity: Uint8Array,
  nonce: Uint8Array,
  pre: TransactionInstruction[],
  post: TransactionInstruction[],
  feePayer: Address | undefined,
  verify: (digest: Uint8Array) => boolean
): Uint8Array {
  const digest = advanceVectorDigest(scheme, nonce, identity, pre, post, feePayer);
  let ok = false;
  try {
    ok = verify(digest);
  } catch {
    ok = false;
  }
  if (!ok) throw new SignatureVerificationError(`${name}: ${SIGNATURE_INVALID}`);
  return digest;
}

// ── Per-scheme verification ──────────────────────────────────────────

/**
 * Verify an Ed25519 `advance` signature offline. `pubkey` is the 32-byte
 * identity, `signature` the 64-byte wire signature (the advance ix data
 * after the 1-byte discriminator). Returns the recomputed digest — the
 * account's next nonce — on success.
 */
export function verifyAdvanceSignatureEd25519(
  pubkey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: Address
): Uint8Array {
  checkInputs("ed25519", nonce, pubkey, 32, signature, ED25519.signatureLen);
  return checkedDigest(
    "ed25519", ED25519, pubkey, nonce, preInstructions, postInstructions,
    feePayer, (digest) => ed25519.verify(signature, digest, pubkey)
  );
}

/**
 * Verify a plain-secp256k1 ECDSA `advance` signature offline.
 * `compressedPubkey` is the 33-byte sec1 identity, `signature` the 64-byte
 * `r || s` wire form. Returns the recomputed digest on success.
 *
 * Verified with `lowS: false`: the on-chain `solana-secp256k1-ecdsa`
 * verifier accepts both `s` normalizations, so the offline check must too
 * or PASS/FAIL would diverge.
 */
export function verifyAdvanceSignatureSecp256k1(
  compressedPubkey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: Address
): Uint8Array {
  checkInputs(
    "secp256k1", nonce, compressedPubkey, SECP256K1.identityLen,
    signature, SECP256K1.signatureLen
  );
  return checkedDigest(
    "secp256k1", SECP256K1, compressedPubkey, nonce, preInstructions,
    postInstructions, feePayer,
    (digest) => secp256k1.verify(signature, digest, compressedPubkey, { lowS: false })
  );
}

/**
 * Verify an EIP-191 `advance` signature offline. `ethAddress` is the
 * 20-byte identity, `signature` the 65-byte `r || s || v` wire form with
 * `v` the raw recovery id (`0..=3`). The key is recovered from the EIP-191
 * envelope of the digest ({@link eip191EnvelopeHash}) and its derived
 * Ethereum address compared to the identity. Returns the recomputed digest
 * on success.
 *
 * The Ethereum legacy `v = 27/28` form is **rejected**: the on-chain
 * program passes `v` straight to `sol_secp256k1_recover`, which errors on
 * recovery ids above 3, so a legacy-form signature would pass offline yet
 * fail on-chain — subtract 27 at assembly time (see
 * {@link normalizeEip191RecoveryByte}).
 */
export function verifyAdvanceSignatureEip191(
  ethAddress: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: Address
): Uint8Array {
  checkInputs(
    "eip191", nonce, ethAddress, EIP191.identityLen, signature, EIP191.signatureLen
  );
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
  const digest = advanceVectorDigest(
    EIP191, nonce, ethAddress, preInstructions, postInstructions, feePayer
  );
  const envelope = eip191EnvelopeHash(digest);
  let recoveredAddress: Uint8Array;
  try {
    const sig = secp256k1.Signature.fromBytes(signature.subarray(0, 64), "compact")
      .addRecoveryBit(v);
    const uncompressed = sig.recoverPublicKey(envelope).toBytes(false);
    recoveredAddress = keccak_256(uncompressed.subarray(1)).subarray(12);
  } catch {
    throw new SignatureVerificationError(`eip191: ${SIGNATURE_INVALID}`);
  }
  if (!bytesEqual(recoveredAddress, ethAddress)) {
    throw new IdentityMismatchError(
      "eip191: recovered Ethereum address does not match the identity"
    );
  }
  return digest;
}

/**
 * Verify a Falcon-512 `advance` signature offline, given the 897-byte wire
 * pubkey (the identity, `sha256(wire_pubkey)`, is derived from it).
 * `signature` is the 666-byte zero-padded wire form; the padding is
 * stripped before handing the compressed stream to the noble verifier.
 * Returns the recomputed digest on success.
 */
export function verifyAdvanceSignatureFalcon512(
  wirePubkey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  signature: Uint8Array,
  feePayer?: Address
): Uint8Array {
  checkInputs(
    "falcon512", nonce, wirePubkey, FALCON_PUBKEY_LEN,
    signature, FALCON512.signatureLen
  );
  return checkedDigest(
    "falcon512", FALCON512, sha256(wirePubkey), nonce, preInstructions,
    postInstructions, feePayer,
    (digest) => nobleFalcon.verify(trimFalconSignature(signature), digest, wirePubkey)
  );
}

