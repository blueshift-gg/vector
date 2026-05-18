/**
 * Hawk-512 (post-quantum) program. Verify-only on-chain; signing is left to
 * the caller. The client identity is `sha256(wire_pubkey)`. Registration is
 * two calls of the same `initialize` instruction (see
 * {@link createInitializeHawk512}).
 *
 * Mirrors `crates/core/src/schemes/hawk512.rs`. Only needs sha256 (node
 * `crypto`, via `../scheme.js`) for identity.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

import {
  Scheme,
  sha256,
  HAWK_PUBKEY_LEN,
  HAWK_SIGNATURE_LEN,
  HAWK_PREPARED_PUBKEY_LEN,
} from "../scheme.js";
import { createInitializeInstruction } from "../instructions.js";

export {
  HAWK_PUBKEY_LEN,
  HAWK_SIGNATURE_LEN,
  HAWK_PREPARED_PUBKEY_LEN,
} from "../scheme.js";

/**
 * Hawk-512 (post-quantum). Client identity is `sha256(wire_pubkey)` (32
 * bytes); the 18 KB prepared pubkey is written by a separate `expand`
 * instruction (two-step registration).
 */
export const HAWK512: Scheme = {
  programId: new PublicKey("Ecm48RMiE4qvyw6m4M5DeutpRAN1AF4tis6ijc6Zq3H9"),
  signatureLen: HAWK_SIGNATURE_LEN,
  identityLen: 32,
  storedIdentityLen: 32 + 7 + HAWK_PREPARED_PUBKEY_LEN,
};

/** Hawk-512 client identity: `sha256(wire_pubkey)` (32 bytes). */
export function hawk512Identity(wirePubkey: Uint8Array): Uint8Array {
  if (wirePubkey.length !== HAWK_PUBKEY_LEN) {
    throw new Error(
      `Hawk-512 wire pubkey must be ${HAWK_PUBKEY_LEN} bytes, got ${wirePubkey.length}`
    );
  }
  return sha256(wirePubkey);
}

/**
 * Hawk-512 registration. Send this instruction **twice with the same
 * accounts and args**: the first call allocates the base account and stores
 * `sha256(wire_pubkey)`; the second (permissionless) call resizes to full
 * and writes the ~18 KB prepared blob. Further calls are idempotent no-ops.
 * Identical to every other scheme's initialize — single-step schemes just
 * finish in one call.
 */
export function createInitializeHawk512(
  payer: PublicKey,
  wirePubkey: Uint8Array
): TransactionInstruction {
  const identity = hawk512Identity(wirePubkey);
  return createInitializeInstruction(payer, HAWK512, identity, wirePubkey);
}
