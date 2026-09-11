/** DKKW25 generalized XMSS. Signing state belongs to the caller. */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { Scheme } from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

// Mirror solana-winternitz's fixed height-8 instance.
export const XMSS_PUBKEY_LEN = 41;
export const XMSS_SIGNATURE_LEN = 1037;

export const XMSS: Scheme = {
  programId: new Address("7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE"),
  signatureLen: XMSS_SIGNATURE_LEN,
  identityLen: XMSS_PUBKEY_LEN,
  storedIdentityLen: XMSS_PUBKEY_LEN,
};

/** Register the immutable public key; its SHA-256 hash is the PDA seed. */
export function createInitializeXmss(
  payer: Address,
  publicKey: Uint8Array
): TransactionInstruction {
  if (publicKey.length !== XMSS_PUBKEY_LEN) {
    throw new Error(`XMSS public key must be ${XMSS_PUBKEY_LEN} bytes`);
  }
  return createInitializeInstruction(payer, XMSS, publicKey, publicKey);
}
