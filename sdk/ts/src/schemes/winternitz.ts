/** DKKW25 one-time Winternitz. Signing state belongs to the caller's persistent signer.
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
export const WINTERNITZ: Scheme = {
  id: 6,
  signatureLen: 849,
  identityLen: 41,
  storedIdentityLen: 41,
  nextKeyLen: 41,
};

/** Initialize a stable account with its first signing key. */
export function createInitializeWinternitz(
  payer: PublicKey,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, WINTERNITZ, publicKey);
}

/**
 * A persistent hash-based signer: `@blueshift-gg/solana-winternitz/signer`'s
 * `SigningKey`, which records its one use before it returns a
 * signature. Never sign with a copy of its key file, or a restored one.
 */
export interface WinternitzSigner {
  sign(message: Uint8Array): { toBytes(): Uint8Array };
}

/**
 * Sign one signer's digest ({@link signerDigest}): `signedDigest(digest)`.
 * For an advance with several signers. The signature spends its leaf even if
 * the transaction never lands: rebroadcast it unchanged, never sign another
 * digest with the same leaf.
 */
export function signDigestWinternitz(signer: WinternitzSigner, digest: Uint8Array): Uint8Array {
  return signer.sign(signedDigest(digest)).toBytes();
}

/**
 * Sign an advance of the account named by `identity` (its first key) and
 * return it, ready to submit. `nextKey` is the key the account holds after
 * it; the digest covers it.
 */
export function signAdvanceInstructionWinternitz(
  signer: WinternitzSigner,
  identity: Uint8Array,
  nonce: Uint8Array,
  nextKey: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey,
  validUntil?: bigint | number
): TransactionInstruction {
  const digest = rotatingAdvanceVectorDigest(
    WINTERNITZ,
    nonce,
    identity,
    nextKey,
    preInstructions,
    postInstructions,
    feePayer,
    validUntil
  );
  return createRotatingAdvanceInstruction(
    WINTERNITZ,
    identity,
    nextKey,
    signDigestWinternitz(signer, digest),
    validUntil
  );
}
