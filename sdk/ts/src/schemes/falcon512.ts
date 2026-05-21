/**
 * Falcon-512 (post-quantum) program: client identity is
 * `sha256(wire_pubkey)`; the on-chain account stores that hash plus the
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
  sha256,
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

/** Falcon-512 — client identity is `sha256(wire_pubkey)` (32 bytes). */
export const FALCON512: Scheme = {
  programId: new Address("HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm"),
  signatureLen: FALCON_SIGNATURE_LEN,
  identityLen: 32,
  storedIdentityLen: 32 + 1 + FALCON_PREPARED_PUBKEY_LEN,
};

/** Falcon-512 client identity: `sha256(wire_pubkey)` (32 bytes). */
export function falcon512Identity(wirePubkey: Uint8Array): Uint8Array {
  if (wirePubkey.length !== FALCON_PUBKEY_LEN) {
    throw new Error(
      `Falcon-512 wire pubkey must be ${FALCON_PUBKEY_LEN} bytes, got ${wirePubkey.length}`
    );
  }
  return sha256(wirePubkey);
}

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
 * prepares the 897-byte wire pubkey; the client identity is its sha256.
 */
export function createInitializeFalcon512(
  payer: Address,
  wirePubkey: Uint8Array
): TransactionInstruction {
  const identity = falcon512Identity(wirePubkey);
  return createInitializeInstruction(payer, FALCON512, identity, wirePubkey);
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
  const identity = falcon512Identity(keypair.publicKey);
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
