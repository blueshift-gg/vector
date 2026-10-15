/** Plain secp256k1 ECDSA. The identity is the 33-byte compressed public key. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { secp256k1 } from "@noble/curves/secp256k1";

import { Scheme } from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

/** Plain secp256k1 ECDSA — identity is the 33-byte compressed pubkey. */
// Checked against the program by `fixtures/schemes.json`.
export const SECP256K1: Scheme = {
  id: 3,
  signatureLen: 64,
  identityLen: 33,
  storedIdentityLen: 33,
  nextKeyLen: 0,
};

/** Plain-secp256k1 identity: the 33-byte compressed pubkey. */
export function secp256k1Identity(privateKey: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(privateKey, true);
}

/**
 * Initialize a plain-secp256k1 vector account. `compressedPubkey` is the
 * 33-byte sec1-compressed pubkey.
 */
export function createInitializeSecp256k1(
  payer: Address,
  compressedPubkey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, SECP256K1, compressedPubkey);
}

/**
 * Sign an advance with a plain secp256k1 key. The signature is the 64-byte
 * `(r, s)`.
 */
export function signAdvanceInstructionSecp256k1(
  privateKey: Uint8Array,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = secp256k1Identity(privateKey);
  const digest = advanceVectorDigest(
    SECP256K1,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );

  const sig = secp256k1.sign(digest, privateKey);
  const sigBytes = sig.toBytes("compact"); // r || s (64 bytes)

  return createAdvanceInstruction(SECP256K1, identity, sigBytes);
}

/**
 * Sign an advance with nothing around it. Landing it only moves the nonce,
 * which cancels everything signed against the old one. It must be the only
 * instruction of its transaction.
 */
export function signRevocationInstructionSecp256k1(
  privateKey: Uint8Array,
  nonce: Uint8Array
): TransactionInstruction {
  return signAdvanceInstructionSecp256k1(privateKey, nonce, [], []);
}
