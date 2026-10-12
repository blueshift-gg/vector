/**
 * Falcon-512 (post-quantum) scheme: client identity is
 * the wire public key; the on-chain account stores the
 * 1024-byte prepared form of the wire pubkey.
 *
 * Mirrors `crates/core/src/schemes/falcon512.rs`. The Rust crate's
 * `solana-falcon512` dep is verify-only, but `@noble/post-quantum/falcon.js`
 * also signs, so the TS SDK implements the full
 * `signAdvanceInstructionFalcon512` flow.
 *
 * The on-chain verifier expects the PQClean *compressed* detached signature
 * zero-padded to 666 bytes — i.e. `falcon512` (not `falcon512padded`, whose
 * fixed-size encoding is a different wire format).
 */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { falcon512 as nobleFalcon } from "@noble/post-quantum/falcon.js";

import {
  Scheme,
  FALCON_PUBKEY_LEN,
  FALCON_SIGNATURE_LEN,
  FALCON_PREPARED_PUBKEY_LEN,
} from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

export {
  FALCON_PUBKEY_LEN,
  FALCON_SIGNATURE_LEN,
  FALCON_PREPARED_PUBKEY_LEN,
} from "../scheme.js";

/** Falcon-512 secret key length (`@noble/post-quantum` encoding). */
export const FALCON_SECRET_KEY_LEN = 1281;

/** Falcon-512. The identity is the 897-byte wire public key. */
export const FALCON512: Scheme = {
  id: 4,
  signatureLen: FALCON_SIGNATURE_LEN,
  identityLen: FALCON_PUBKEY_LEN,
  storedIdentityLen: FALCON_PREPARED_PUBKEY_LEN,
  nextKeyLen: 0,
  nextKeyOptional: false,
};

/** Falcon-512 keypair: 1281-byte secret + 897-byte wire pubkey. */
export interface Falcon512Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/** Generate a Falcon-512 keypair (897-byte wire pubkey, 1281-byte secret). */
export function falcon512Keygen(seed?: Uint8Array): Falcon512Keypair {
  const kp = seed ? nobleFalcon.keygen(seed) : nobleFalcon.keygen();
  return {
    secretKey: Uint8Array.from(kp.secretKey),
    publicKey: Uint8Array.from(kp.publicKey),
  };
}

/** Derive the 897-byte Falcon-512 wire pubkey from a secret key. */
export function falcon512PublicKey(secretKey: Uint8Array): Uint8Array {
  return Uint8Array.from(nobleFalcon.getPublicKey(secretKey));
}

/**
 * Initialize a Falcon-512 vector account. The on-chain program hashes and
 * prepares the 897-byte wire pubkey, which is also the client identity.
 */
export function createInitializeFalcon512(
  payer: Address,
  wirePubkey: Uint8Array
): TransactionInstruction {
  return createInitializeInstruction(payer, FALCON512, wirePubkey);
}

/**
 * Sign the advance digest with a Falcon-512 keypair and return a
 * ready-to-submit advance instruction. The variable-length compressed
 * detached signature is zero-padded to the 666-byte wire format the
 * on-chain verifier expects.
 */
export function signAdvanceInstructionFalcon512(
  keypair: Falcon512Keypair,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = keypair.publicKey;
  const digest = advanceVectorDigest(
    FALCON512,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );

  const detached = Uint8Array.from(nobleFalcon.sign(digest, keypair.secretKey));
  if (detached.length > FALCON_SIGNATURE_LEN) {
    throw new Error(
      `Falcon-512 signature ${detached.length} B exceeds wire size ${FALCON_SIGNATURE_LEN}`
    );
  }
  // Zero-pad the compressed detached signature to the fixed 666-byte wire
  // format `solana-falcon512` reads (matches PQClean's `CRYPTO_BYTES`).
  const signature = new Uint8Array(FALCON_SIGNATURE_LEN);
  signature.set(detached, 0);

  return createAdvanceInstruction(FALCON512, identity, signature);
}
