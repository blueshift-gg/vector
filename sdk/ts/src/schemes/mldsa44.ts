/** ML-DSA-44 with an empty FIPS 204 context. Mirrors the Rust scheme. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";

import { Scheme } from "../scheme.js";
import {
  createInitializeInstructions,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

/** ML-DSA-44 secret key length (FIPS 204 Table 2). */
export const MLDSA44_SECRET_KEY_LEN = 2560;
/**
 * ML-DSA-44 — the identity is the public key (1,312 bytes); the account
 * also stores its prepared form (20,544 bytes).
 */
// Checked against the program by `fixtures/schemes.json`.
export const MLDSA44: Scheme = {
  id: 5,
  signatureLen: 2420,
  identityLen: 1312,
  storedIdentityLen: 1312 + 20544,
  nextKeyLen: 0,
};

/** ML-DSA-44 keypair: 2,560-byte secret + 1,312-byte public key. */
export interface MlDsa44Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate an ML-DSA-44 keypair (FIPS 204 Algorithm 1; 32-byte seed). */
export function mldsa44Keygen(seed?: Uint8Array): MlDsa44Keypair {
  const kp = seed ? ml_dsa44.keygen(seed) : ml_dsa44.keygen();
  return {
    secretKey: Uint8Array.from(kp.secretKey),
    publicKey: Uint8Array.from(kp.publicKey),
  };
}

/** Derive the 1,312-byte public key from a secret key. */
export function mldsa44PublicKey(secretKey: Uint8Array): Uint8Array {
  return Uint8Array.from(ml_dsa44.getPublicKey(secretKey));
}

/**
 * Create an ML-DSA-44 account: three `initialize` instructions. Put them in
 * one transaction (a V1 transaction: the key alone is 1,313 bytes of
 * instruction data) with a 1.4M compute budget.
 */
export function createInitializeMlDsa44(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction[] {
  return createInitializeInstructions(payer, MLDSA44, publicKey);
}

/**
 * Sign the advance digest with an ML-DSA-44 keypair (empty context) and
 * return a ready-to-submit advance instruction. The 2,420-byte signature
 * needs a V1 transaction.
 */
export function signAdvanceInstructionMlDsa44(
  keypair: MlDsa44Keypair,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = keypair.publicKey;
  const digest = advanceVectorDigest(
    MLDSA44,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = Uint8Array.from(ml_dsa44.sign(digest, keypair.secretKey));
  return createAdvanceInstruction(MLDSA44, identity, signature);
}
