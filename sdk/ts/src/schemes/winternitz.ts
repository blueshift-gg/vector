/** DKKW25 one-time Winternitz. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme, sha256 } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's one-time instance.
export const WINTERNITZ_PUBKEY_LEN = 41;
export const WINTERNITZ_SIGNATURE_LEN = 849;

export const WINTERNITZ: Scheme = {
  programId: new Address("GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf"),
  signatureLen: WINTERNITZ_SIGNATURE_LEN,
  identityLen: 32,
  storedIdentityLen: 32 + WINTERNITZ_PUBKEY_LEN,
};

/** Derive the permanent account identity. Do not recompute it on rotation. */
export function winternitzIdentity(initialPublicKey: Uint8Array): Uint8Array {
  if (initialPublicKey.length !== WINTERNITZ_PUBKEY_LEN) {
    throw new Error(`Winternitz public key must be ${WINTERNITZ_PUBKEY_LEN} bytes`);
  }
  return sha256(initialPublicKey);
}

/** Initialize a stable account with its first signing key. */
export function createInitializeWinternitz(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, WINTERNITZ, winternitzIdentity(publicKey), publicKey);
}
