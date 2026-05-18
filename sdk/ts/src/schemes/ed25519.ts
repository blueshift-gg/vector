/**
 * Ed25519 program: identity is the 32-byte public key, verified directly
 * over the advance digest.
 *
 * Mirrors `crates/core/src/schemes/ed25519.rs`. Pulls in only
 * `@noble/curves/ed25519`.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";

import { Scheme } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

/** Ed25519 — identity is the 32-byte public key. */
export const ED25519: Scheme = {
  programId: new PublicKey("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV"),
  signatureLen: 64,
  identityLen: 32,
  storedIdentityLen: 32,
};

/** Ed25519 identity (32-byte public key) for a private key seed. */
export function ed25519Identity(signingKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(signingKey);
}

/** Initialize an Ed25519 vector account. `pubkey` is the 32-byte public key. */
export function createInitializeEd25519(
  payer: PublicKey,
  pubkey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, ED25519, pubkey, pubkey);
}

/**
 * Sign the advance digest with an Ed25519 key and return a ready-to-submit
 * advance instruction.
 * @param signingKey 32-byte Ed25519 private key seed
 */
export function signAdvanceInstruction(
  signingKey: Uint8Array,
  nonce: Uint8Array,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): TransactionInstruction {
  const identity = ed25519Identity(signingKey);
  const digest = advanceVectorDigest(
    ED25519,
    nonce,
    identity,
    subInstructions,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = ed25519.sign(digest, signingKey);
  return createAdvanceInstruction(ED25519, identity, signature, subInstructions);
}
