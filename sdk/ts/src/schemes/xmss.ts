/** DKKW25 generalized XMSS. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme, sha256 } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's fixed height-8 instance.
export const XMSS_PUBKEY_LEN = 41;
export const XMSS_SIGNATURE_LEN = 1037;

export const XMSS: Scheme = {
  programId: new Address("7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE"),
  signatureLen: XMSS_SIGNATURE_LEN,
  identityLen: 32,
  storedIdentityLen: 32 + XMSS_PUBKEY_LEN,
};

/** Derive the permanent account identity. Do not recompute it on rotation. */
export function xmssIdentity(initialPublicKey: Uint8Array): Uint8Array {
  if (initialPublicKey.length !== XMSS_PUBKEY_LEN) {
    throw new Error(`XMSS public key must be ${XMSS_PUBKEY_LEN} bytes`);
  }
  return sha256(initialPublicKey);
}

/** Initialize a stable account with its first signing key. */
export function createInitializeXmss(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, XMSS, xmssIdentity(publicKey), publicKey);
}
