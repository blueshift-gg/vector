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
  createAdvanceInstruction,
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

/**
 * Shared digest: `SHA256(buffer[..sigStart] || nonce || identity ||
 * buffer[sigEnd..])`. `identity` is the scheme's client identity bytes (for
 * Falcon/Hawk, `sha256(wire_pubkey)`).
 */
function vectorDigest(
  targetIx: TransactionInstruction,
  targetIndex: number,
  sigLen: number,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  const allIxs = [...preInstructions, targetIx, ...postInstructions];
  const promoted = promoteToMessageFlags(allIxs, feePayer);
  const buffer = constructInstructionsData(promoted);
  // Patch the sysvar's `current_instruction_index` footer (last 2 bytes) to
  // match what the runtime will write at execution time. The footer is part
  // of `post`, which is folded into the hash, so the off-chain digest only
  // matches when this index is correct (a no-op for single-ix advance, but
  // non-zero when there are pre-instructions like Hawk's CU bump).
  writeU16LE(buffer, targetIndex, buffer.length - 2);

  const ixOffsetPos = 2 + 2 * targetIndex;
  const ixOffset = readU16LE(buffer, ixOffsetPos);

  const numAccounts = readU16LE(buffer, ixOffset);
  const sigStart = ixOffset + 2 + 33 * numAccounts + 32 + 2 + 1;
  const sigEnd = sigStart + sigLen;

  const h = createHash("sha256");
  h.update(buffer.subarray(0, sigStart));
  h.update(nonce);
  h.update(identity);
  h.update(buffer.subarray(sigEnd));
  return new Uint8Array(h.digest());
}

/**
 * Compute the canonical `advance_vector_digest` the client must sign over.
 * Callers thread the full ix layout via `pre`/`post`; the advance ix is
 * inserted at `pre.length`. Any sibling `passthrough` ix authorising CPIs
 * under the vector PDA's signer seeds is just another pre/post ix — its
 * bytes get committed to by the digest like any other tx ix, which is
 * what authenticates the passthrough end-to-end.
 */
export function advanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  const sigLen = scheme.signatureLen;
  const placeholder = new Uint8Array(sigLen);
  const advanceIx = createAdvanceInstruction(scheme, identity, placeholder);
  return vectorDigest(
    advanceIx,
    preInstructions.length,
    sigLen,
    nonce,
    identity,
    preInstructions,
    postInstructions,
    feePayer
  );
}
