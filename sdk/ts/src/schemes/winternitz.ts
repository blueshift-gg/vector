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

/** Initialize a stable account with its first signing key. */
export function createInitializeWinternitz(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, WINTERNITZ, publicKey);
}
