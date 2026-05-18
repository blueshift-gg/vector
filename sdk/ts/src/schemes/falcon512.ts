/**
 * Falcon-512 (post-quantum) program: client identity is
 * `sha256(wire_pubkey)`; the on-chain program is verify-only and stores the
 * 897-byte wire pubkey hashed + prepared.
 *
 * Mirrors `crates/core/src/schemes/falcon512.rs`, but — unlike the Rust
 * crate, whose `solana-falcon512` dep is verify-only — the TS SDK has a
 * Falcon signer via `@noble/post-quantum/falcon.js`, so it implements the
 * full `signAdvanceInstructionFalcon512` flow.
 *
 * The on-chain verifier (`solana-falcon512`) expects the PQClean *compressed*
 * detached signature zero-padded to 666 bytes — i.e. `falcon512` (not
 * `falcon512padded`, whose fixed-size encoding is a different wire format).
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
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
  programId: new PublicKey("HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm"),
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

/** Generate a Falcon-512 keypair (897-byte wire pubkey, 1281-byte secret). */
export function falcon512Keygen(
  seed?: Uint8Array
): { secretKey: Uint8Array; publicKey: Uint8Array } {
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
  payer: PublicKey,
  wirePubkey: Uint8Array
): TransactionInstruction {
  const identity = falcon512Identity(wirePubkey);
  return createInitializeInstruction(payer, FALCON512, identity, wirePubkey);
}

/**
 * Sign the advance digest with a Falcon-512 secret key and return a
 * ready-to-submit advance instruction. The 897-byte wire pubkey is derived
 * from the secret key; the variable-length compressed detached signature is
 * zero-padded to the 666-byte wire format the on-chain verifier expects.
 * @param secretKey 1281-byte Falcon-512 secret key
 */
export function signAdvanceInstructionFalcon512(
  secretKey: Uint8Array,
  nonce: Uint8Array,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): TransactionInstruction {
  const wirePubkey = falcon512PublicKey(secretKey);
  const identity = falcon512Identity(wirePubkey);
  const digest = advanceVectorDigest(
    FALCON512,
    nonce,
    identity,
    subInstructions,
    preInstructions,
    postInstructions,
    feePayer
  );

  const detached = Uint8Array.from(nobleFalcon.sign(digest, secretKey));
  if (detached.length > FALCON_SIGNATURE_LEN) {
    throw new Error(
      `Falcon-512 signature ${detached.length} B exceeds wire size ${FALCON_SIGNATURE_LEN}`
    );
  }
  // Zero-pad the compressed detached signature to the fixed 666-byte wire
  // format `solana-falcon512` reads (matches PQClean's `CRYPTO_BYTES`).
  const signature = new Uint8Array(FALCON_SIGNATURE_LEN);
  signature.set(detached, 0);

  return createAdvanceInstruction(FALCON512, identity, signature, subInstructions);
}
