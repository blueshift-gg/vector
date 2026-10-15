/** Ed25519. The identity is the 32-byte public key. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";

import { Scheme } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

/** Ed25519 — identity is the 32-byte public key. */
// Checked against the program by `fixtures/program.json`.
export const ED25519: Scheme = {
  id: 1,
  signatureLen: 64,
  identityLen: 32,
  storedIdentityLen: 32,
  nextKeyLen: 0,
};

/** Ed25519 identity (32-byte public key) for a private key seed. */
export function ed25519Identity(signingKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(signingKey);
}

/** Initialize an Ed25519 vector account. `pubkey` is the 32-byte public key. */
export function createInitializeEd25519(
  payer: Address,
  pubkey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, ED25519, pubkey);
}

/**
 * Sign the advance digest with an Ed25519 key and return a ready-to-submit
 * advance instruction.
 * @param signingKey 32-byte Ed25519 private key seed
 */
export function signAdvanceInstructionEd25519(
  signingKey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = ed25519Identity(signingKey);
  const digest = advanceVectorDigest(
    ED25519,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = ed25519.sign(digest, signingKey);
  return createAdvanceInstruction(ED25519, identity, signature);
}

/**
 * Sign an advance with nothing around it. Landing it only moves the nonce,
 * which cancels everything signed against the old one. It must be the only
 * instruction of its transaction.
 */
export function signRevocationInstructionEd25519(
  signingKey: Uint8Array,
  nonce: Uint8Array
): TransactionInstruction {
  return signAdvanceInstructionEd25519(signingKey, nonce, [], []);
}
