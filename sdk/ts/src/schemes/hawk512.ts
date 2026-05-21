/**
 * Hawk-512 (post-quantum) program: client identity is `sha256(wire_pubkey)`;
 * the on-chain account stores that hash plus the 18 KB prepared form of the
 * wire pubkey.
 *
 * Mirrors `crates/core/src/schemes/hawk512.rs`. The Rust crate's
 * `solana-hawk512` dep is verify-only, but
 * [`@blueshift-gg/hawk512`](https://www.npmjs.com/package/@blueshift-gg/hawk512)
 * also signs, so the TS SDK implements the full
 * `signAdvanceInstructionHawk512` flow. The 555-byte detached signature is
 * the exact wire format `solana-hawk512` verifies.
 *
 * Registration is three permissionless ixs (see
 * {@link createInitializeHawk512}).
 */
import { Address, TransactionInstruction } from "@solana/web3.js";
import { hawk512 as nobleHawk, shakeStream } from "@blueshift-gg/hawk512";

import {
  Scheme,
  sha256,
  findVectorPda,
  HAWK_PUBKEY_LEN,
  HAWK_SIGNATURE_LEN,
  HAWK_PREPARED_PUBKEY_LEN,
  INITIALIZE_DISCRIMINATOR,
} from "../scheme.js";
import {
  createInitializeInstruction,
  createAdvanceInstruction,
} from "../instructions.js";
import { advanceVectorDigest } from "../digest.js";

export {
  HAWK_PUBKEY_LEN,
  HAWK_SIGNATURE_LEN,
  HAWK_PREPARED_PUBKEY_LEN,
} from "../scheme.js";

/** Hawk-512 secret key length (`@blueshift-gg/hawk512` encoding). */
export const HAWK_SECRET_KEY_LEN = 184;

/** Hawk-512 keypair: 184-byte secret + 1024-byte wire pubkey. */
export interface Hawk512Keypair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Hawk-512 (post-quantum). Client identity is `sha256(wire_pubkey)` (32
 * bytes); the 18 KB prepared pubkey is written by two follow-up
 * permissionless calls (see {@link createInitializeHawk512}).
 */
export const HAWK512: Scheme = {
  programId: new Address("Ecm48RMiE4qvyw6m4M5DeutpRAN1AF4tis6ijc6Zq3H9"),
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
 * Generate a Hawk-512 keypair (1024-byte wire pubkey, 184-byte secret).
 * Pass a `seed` for deterministic generation — a continuous `SHAKE256(seed)`
 * stream identical to the Rust `hawk512::xof::RngContext`, so the same seed
 * yields the same keypair in both languages.
 */
export function hawk512Keygen(seed?: Uint8Array): Hawk512Keypair {
  const kp = seed ? nobleHawk.keygen(shakeStream(seed)) : nobleHawk.keygen();
  return {
    secretKey: Uint8Array.from(kp.secretKey),
    publicKey: Uint8Array.from(kp.publicKey),
  };
}

/**
 * Hawk-512 registration step 1 — `initialize`. Commits the 32-byte
 * `sha256(wire_pubkey)` and allocates the ~10 KB base account, prefunding
 * full rent. Carries the `system_program` meta for `CreateAccount`.
 *
 * Registration is three permissionless ixs, each in its own tx:
 * 1. {@link createInitializeHawk512} — commit hash + allocate.
 * 2. {@link createHawk512StoreWire} — verify `sha256(wire) == commit` and
 *    stash the wire in the account.
 * 3. {@link createHawk512Finalize} — resize to ~18.5 KB and run
 *    `prepare_into` on the stashed wire. Must ship with a
 *    `ComputeBudgetProgram.setComputeUnitLimit(600_000)` ix to cover
 *    `prepare_into`'s ~410 k-CU draw (the 200 k per-tx default isn't
 *    enough).
 *
 * The 3-tx split is forced by the 1232-byte tx ceiling: the 1024-byte wire
 * payload can't coexist with the `system_program` meta required by
 * `CreateAccount`, and `finalize`'s CU need can't coexist with the wire
 * payload either. The flow is grief-proof — see the comment on step 2.
 */
export function createInitializeHawk512(
  payer: Address,
  wirePubkey: Uint8Array
): TransactionInstruction {
  const identity = hawk512Identity(wirePubkey);
  return createInitializeInstruction(payer, HAWK512, identity, identity);
}

/**
 * Hawk-512 registration step 2 — `store_wire`. Ships the 1024-byte wire
 * pubkey; the program verifies `sha256(payload) == stored hash` (the
 * commit from step 1) before stashing. The hash verify is the
 * grief-prevention anchor: an attacker who squats on step 1 can neither
 * block this step nor corrupt the stashed wire, because only callers who
 * have the actual wire bytes can pass the check.
 *
 * Accounts: `[vector_pda]` only — no payer, no system_program. Trimming
 * those metas is what gets the 1024-byte payload to fit alongside the
 * tx-level fee payer signer under the 1232-byte ceiling.
 */
export function createHawk512StoreWire(
  wirePubkey: Uint8Array
): TransactionInstruction {
  if (wirePubkey.length !== HAWK_PUBKEY_LEN) {
    throw new Error(
      `Hawk-512 wire pubkey must be ${HAWK_PUBKEY_LEN} bytes, got ${wirePubkey.length}`
    );
  }
  const identity = hawk512Identity(wirePubkey);
  const [vectorPda] = findVectorPda(HAWK512, identity);
  const data = new Uint8Array(1 + HAWK_PUBKEY_LEN);
  data[0] = INITIALIZE_DISCRIMINATOR;
  data.set(wirePubkey, 1);
  return new TransactionInstruction({
    programId: HAWK512.programId,
    keys: [{ pubkey: vectorPda, isSigner: false, isWritable: true }],
    data: Buffer.from(data),
  });
}

/**
 * Hawk-512 registration step 3 — `finalize`. Resizes the account to
 * ~18.5 KB and runs Hawk's `prepare_into` on the wire stashed by step 2.
 * Idempotent. The tx must ship with a
 * `ComputeBudgetProgram.setComputeUnitLimit(600_000)` ix to cover
 * `prepare_into`'s ~410 k-CU draw on the live validator (the 200 k per-tx
 * default isn't enough).
 *
 * Same `initialize` discriminator as steps 1 and 2; the on-chain
 * dispatcher selects this handler by ix shape (1 meta + empty data) and
 * account state.
 */
export function createHawk512Finalize(
  wirePubkey: Uint8Array
): TransactionInstruction {
  const identity = hawk512Identity(wirePubkey);
  const [vectorPda] = findVectorPda(HAWK512, identity);
  return new TransactionInstruction({
    programId: HAWK512.programId,
    keys: [{ pubkey: vectorPda, isSigner: false, isWritable: true }],
    data: Buffer.from([INITIALIZE_DISCRIMINATOR]),
  });
}

/**
 * Sign the advance digest with a Hawk-512 keypair and return a
 * ready-to-submit advance instruction. The 555-byte detached signature is
 * the exact wire format `solana-hawk512` verifies (fixed-size, no padding
 * needed — unlike Falcon). Unlike Falcon, `@blueshift-gg/hawk512` has no
 * `getPublicKey`, so the wire pubkey must be carried alongside the secret.
 */
export function signAdvanceInstructionHawk512(
  keypair: Hawk512Keypair,
  nonce: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction {
  const identity = hawk512Identity(keypair.publicKey);
  const digest = advanceVectorDigest(
    HAWK512,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );

  const signature = Uint8Array.from(nobleHawk.sign(digest, keypair.secretKey));
  if (signature.length !== HAWK_SIGNATURE_LEN) {
    throw new Error(
      `Hawk-512 signature ${signature.length} B != wire size ${HAWK_SIGNATURE_LEN}`
    );
  }

  return createAdvanceInstruction(HAWK512, identity, signature);
}
