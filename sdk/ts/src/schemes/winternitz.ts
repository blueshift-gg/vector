/** DKKW25 one-time Winternitz. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

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
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, WINTERNITZ, publicKey);
}
