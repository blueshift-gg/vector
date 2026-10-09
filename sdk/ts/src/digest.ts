/**
 * The canonical `advance` digest the client signs and the on-chain program
 * recomputes from the instructions sysvar.
 *
 * Mirrors `crates/core/src/digest.rs`.
 */
import { createHash } from "crypto";
import { Address, TransactionInstruction } from "@solana/web3.js";

import { Scheme, readU16LE, writeU16LE } from "./scheme.js";
import {
  createMultiAdvanceInstruction,
  constructInstructionsData,
} from "./instructions.js";

/**
 * Promote instruction-level account flags to message-level flags, matching
 * what the Solana runtime writes into the instructions sysvar.
 */
function promoteToMessageFlags(
  instructions: TransactionInstruction[],
  feePayer?: Address
): TransactionInstruction[] {
  const flagMap = new Map<string, { isSigner: boolean; isWritable: boolean }>();

  if (feePayer) {
    flagMap.set(feePayer.toBase58(), { isSigner: true, isWritable: true });
  }

  for (const ix of instructions) {
    for (const meta of ix.keys) {
      const key = meta.pubkey.toBase58();
      const existing = flagMap.get(key);
      if (existing) {
        existing.isSigner = existing.isSigner || meta.isSigner;
        existing.isWritable = existing.isWritable || meta.isWritable;
      } else {
        flagMap.set(key, {
          isSigner: meta.isSigner,
          isWritable: meta.isWritable,
        });
      }
    }
  }

  return instructions.map(
    (ix) =>
      new TransactionInstruction({
        programId: ix.programId,
        keys: ix.keys.map((meta) => {
          const promoted = flagMap.get(meta.pubkey.toBase58())!;
          return {
            pubkey: meta.pubkey,
            isSigner: promoted.isSigner,
            isWritable: promoted.isWritable,
          };
        }),
        data: ix.data,
      })
  );
}

/** One signer of an `advance`: its scheme and identity. */
export type AdvanceSigner = { scheme: Scheme; identity: Uint8Array };

/**
 * The message every signer of one `advance` approves: the SHA-256 of the
 * instructions sysvar with the signatures cut off the end of the advance's
 * data. The advance is inserted at `preInstructions.length`; a sibling
 * `passthrough` is just another pre/post instruction, and the message
 * covers all of it.
 *
 * Mirrors `advance_message` in `crates/core/src/digest.rs`.
 */
export function advanceMessage(
  signers: AdvanceSigner[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  const advanceIx = createMultiAdvanceInstruction(
    signers.map((signer) => ({
      ...signer,
      signature: new Uint8Array(signer.scheme.signatureLen),
    }))
  );
  const advanceIndex = preInstructions.length;
  const buffer = constructInstructionsData(
    promoteToMessageFlags(
      [...preInstructions, advanceIx, ...postInstructions],
      feePayer
    )
  );
  // The runtime sets the footer to the executing instruction's index.
  writeU16LE(buffer, advanceIndex, buffer.length - 2);

  // Region: num_accounts (u16) + 33 * N metas + 32-byte program id +
  // u16 data_len + data. The signatures follow the discriminator and one
  // scheme byte per signer, and run to the end of the data.
  const offset = readU16LE(buffer, 2 + 2 * advanceIndex);
  const dataStart = offset + 2 + 33 * advanceIx.keys.length + 32 + 2;
  const signaturesStart = dataStart + 1 + signers.length;
  const dataEnd = dataStart + advanceIx.data.length;

  const h = createHash("sha256");
  h.update(buffer.subarray(0, signaturesStart));
  h.update(buffer.subarray(dataEnd));
  return new Uint8Array(h.digest());
}

/**
 * What one signer signs: `SHA256(message || nonce || identity)`, with
 * `message` from {@link advanceMessage}. It is also the account's next
 * nonce. `identity` is the scheme's client identity bytes (for Falcon,
 * `sha256(wire_pubkey)`).
 *
 * Mirrors `signer_digest` in `crates/core/src/digest.rs`.
 */
export function signerDigest(
  message: Uint8Array,
  nonce: Uint8Array,
  identity: Uint8Array
): Uint8Array {
  const h = createHash("sha256");
  h.update(message);
  h.update(nonce);
  h.update(identity);
  return new Uint8Array(h.digest());
}

/** {@link signerDigest} for an advance with one signer. */
export function advanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  const message = advanceMessage(
    [{ scheme, identity }],
    preInstructions,
    postInstructions,
    feePayer
  );
  return signerDigest(message, nonce, identity);
}

/**
 * The digest a pre-signed revocation commits to: {@link advanceVectorDigest}
 * with empty pre/post instructions. The resulting advance is an inert
 * transition — landing it only installs the next nonce, orphaning every
 * signature pre-signed against `nonce` (a kill-switch).
 *
 * This digest commits to the instructions sysvar of the broadcasting
 * transaction, so a pre-signed revocation must be broadcast as a transaction
 * containing ONLY the advance instruction. ed25519 / eip191 / secp256k1
 * inert advances fit the default compute budget (~13k / ~26k / ~72k CUs);
 * for Falcon-512, sign via the advance signer with a compute-budget
 * pre-instruction committed at sign time (its ~184k CU verify leaves no
 * headroom under the 200k default).
 *
 * Mirrors `revocation_digest` in `crates/core/src/digest.rs`.
 */
export function revocationDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array
): Uint8Array {
  return advanceVectorDigest(scheme, nonce, identity, [], []);
}
