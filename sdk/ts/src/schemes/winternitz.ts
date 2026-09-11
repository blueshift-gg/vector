/** DKKW25 one-time Winternitz. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's one-time instance.
export const WINTERNITZ_PUBKEY_LEN = 41;
export const WINTERNITZ_SIGNATURE_LEN = 849;

export const WINTERNITZ: Scheme = {
  programId: new Address("GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf"),
  signatureLen: WINTERNITZ_SIGNATURE_LEN,
  identityLen: WINTERNITZ_PUBKEY_LEN,
  storedIdentityLen: WINTERNITZ_PUBKEY_LEN,
};

/** Register the immutable public key; its SHA-256 hash is the PDA seed. */
export function createInitializeWinternitz(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  if (publicKey.length !== WINTERNITZ_PUBKEY_LEN) {
    throw new Error(`Winternitz public key must be ${WINTERNITZ_PUBKEY_LEN} bytes`);
  }
  return createInitializeInstruction(payer, WINTERNITZ, publicKey, publicKey);
}
