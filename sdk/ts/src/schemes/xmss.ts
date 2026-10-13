/** DKKW25 generalized XMSS. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's fixed height-8 instance.
export const XMSS_PUBKEY_LEN = 41;
export const XMSS_SIGNATURE_LEN = 1037;

export const XMSS: Scheme = {
  id: 7,
  signatureLen: XMSS_SIGNATURE_LEN,
  identityLen: XMSS_PUBKEY_LEN,
  // The key, then the lowest leaf that may sign next (u32 LE).
  storedIdentityLen: XMSS_PUBKEY_LEN + 4,
  nextKeyLen: XMSS_PUBKEY_LEN,
  nextKeyOptional: true,
};

/** Initialize a stable account with its first signing key. */
export function createInitializeXmss(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, XMSS, publicKey);
}
