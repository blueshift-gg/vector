/** DKKW25 generalized XMSS. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

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
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, XMSS, publicKey);
}
