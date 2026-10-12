/** DKKW25 one-time Winternitz. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's one-time instance.
export const WINTERNITZ_PUBKEY_LEN = 41;
export const WINTERNITZ_SIGNATURE_LEN = 849;

export const WINTERNITZ: Scheme = {
  id: 6,
  signatureLen: WINTERNITZ_SIGNATURE_LEN,
  identityLen: WINTERNITZ_PUBKEY_LEN,
  storedIdentityLen: WINTERNITZ_PUBKEY_LEN,
  nextKeyLen: WINTERNITZ_PUBKEY_LEN,
  nextKeyOptional: false,
};

/**
 * The permanent account identity: the first public key. Keep using it after
 * the key rotates.
 */
export function winternitzIdentity(initialPublicKey: Uint8Array): Uint8Array {
  if (initialPublicKey.length !== WINTERNITZ_PUBKEY_LEN) {
    throw new Error(`Winternitz public key must be ${WINTERNITZ_PUBKEY_LEN} bytes`);
  }
  return initialPublicKey;
}

/** Initialize a stable account with its first signing key. */
export function createInitializeWinternitz(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, WINTERNITZ, winternitzIdentity(publicKey), publicKey);
}
