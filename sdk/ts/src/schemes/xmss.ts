/** DKKW25 generalized XMSS. Signing state belongs to the caller's persistent signer.
 *
 * A one-time key signs 32 bytes: `signedDigest(digest)`, the SHA-256 of
 * `"vector:" || digest`, where `digest` is `rotatingAdvanceVectorDigest`'s.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import {
  createInitializeInstruction,
  createRotatingAdvanceInstruction,
} from "../instructions.js";
import { rotatingAdvanceVectorDigest, signedDigest } from "../digest.js";

// Checked against the program by `fixtures/program.json`.
export const XMSS: Scheme = {
  id: 7,
  signatureLen: 1037,
  identityLen: 41,
  // The key, then the lowest leaf that may sign next (u32 LE).
  storedIdentityLen: 41 + 4,
  nextKeyLen: 41,
};

/** Initialize a stable account with its first signing key. */
export function createInitializeXmss(
  payer: PublicKey,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, XMSS, publicKey);
}

/**
 * A persistent hash-based signer: `@blueshift-gg/solana-xmss/signer`'s
 * `SigningKey`, which records each leaf as used before it returns a
 * signature. Never sign with a copy of its key file, or a restored one.
 */
export interface XmssSigner {
  sign(message: Uint8Array): { toBytes(): Uint8Array };
}

/**
 * Sign one signer's digest ({@link signerDigest}): `signedDigest(digest)`.
 * For an advance with several signers. The signature spends its leaf even if
 * the transaction never lands: rebroadcast it unchanged, never sign another
 * digest with the same leaf. Sync it with the account's leaf counter first: `signer.requireNextLeafAtLeast(nextLeaf)`.
 */
export function signDigestXmss(signer: XmssSigner, digest: Uint8Array): Uint8Array {
  return signer.sign(signedDigest(digest)).toBytes();
}

/**
 * Sign an advance of the account named by `identity` (its first key) and
 * return it, ready to submit. `nextKey` is the key the account holds after
 * it; the digest covers it. Sync it with the account's leaf counter first: `signer.requireNextLeafAtLeast(nextLeaf)`.
 */
export function signAdvanceInstructionXmss(
  signer: XmssSigner,
  identity: Uint8Array,
  nonce: Uint8Array,
  nextKey: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey,
  validUntil?: bigint | number
): TransactionInstruction {
  const digest = rotatingAdvanceVectorDigest(
    XMSS,
    nonce,
    identity,
    nextKey,
    preInstructions,
    postInstructions,
    feePayer,
    validUntil
  );
  return createRotatingAdvanceInstruction(
    XMSS,
    identity,
    nextKey,
    signDigestXmss(signer, digest),
    validUntil
  );
}
