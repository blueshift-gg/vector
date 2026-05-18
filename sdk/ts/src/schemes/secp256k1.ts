/**
 * Plain secp256k1 ECDSA program: identity is the 33-byte sec1-compressed
 * pubkey, verified via standard ECDSA (no envelope, no recovery byte).
 *
 * Mirrors `crates/core/src/schemes/secp256k1.rs`. Pulls in only
 * `@noble/curves/secp256k1`.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { secp256k1 } from "@noble/curves/secp256k1";

import { Scheme, SECP256K1_COMPRESSED_PUBKEY_LEN } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

/** Plain secp256k1 ECDSA — identity is the 33-byte compressed pubkey. */
export const SECP256K1: Scheme = {
  programId: new PublicKey("9NCknbW4LpePSZzbZGFk2HHsSH4y4pkmRjEguJo7qqjd"),
  signatureLen: 64,
  identityLen: SECP256K1_COMPRESSED_PUBKEY_LEN,
  storedIdentityLen: SECP256K1_COMPRESSED_PUBKEY_LEN,
};

/** 33-byte sec1-compressed secp256k1 public key. */
export function secp256k1CompressedPubkey(privateKey: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(privateKey, true);
}

/** Plain-secp256k1 identity: the 33-byte compressed pubkey. */
export function secp256k1Identity(privateKey: Uint8Array): Uint8Array {
  return secp256k1CompressedPubkey(privateKey);
}

/**
 * Initialize a plain-secp256k1 vector account. `compressedPubkey` is the
 * 33-byte sec1-compressed pubkey.
 */
export function createInitializeSecp256k1(
  payer: PublicKey,
  compressedPubkey: Uint8Array
): TransactionInstruction {
  if (compressedPubkey.length !== SECP256K1_COMPRESSED_PUBKEY_LEN) {
    throw new Error(
      `compressed pubkey must be ${SECP256K1_COMPRESSED_PUBKEY_LEN} bytes, got ${compressedPubkey.length}`
    );
  }
  return createInitializeInstruction(
    payer,
    SECP256K1,
    compressedPubkey,
    compressedPubkey
  );
}

/**
 * Sign the advance digest with a plain secp256k1 ECDSA key (no EIP-191
 * envelope) and return a ready-to-submit advance instruction. Signature is
 * 64 bytes `(r, s)`.
 * @param privateKey 32-byte secp256k1 private key
 */
export function signAdvanceInstructionSecp256k1(
  privateKey: Uint8Array,
  nonce: Uint8Array,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): TransactionInstruction {
  const identity = secp256k1Identity(privateKey);
  const digest = advanceVectorDigest(
    SECP256K1,
    nonce,
    identity,
    subInstructions,
    preInstructions,
    postInstructions,
    feePayer
  );

  const sig = secp256k1.sign(digest, privateKey);
  const sigBytes = sig.toCompactRawBytes(); // r || s (64 bytes)

  return createAdvanceInstruction(
    SECP256K1,
    identity,
    sigBytes,
    subInstructions
  );
}
