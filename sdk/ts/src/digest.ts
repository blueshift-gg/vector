/**
 * The canonical `advance` digest the client signs and the on-chain program
 * recomputes from the instructions sysvar.
 *
 * Mirrors `crates/core/src/digest.rs`.
 */
import { createHash } from "crypto";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

import { Scheme, readU16LE } from "./scheme.js";
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
  feePayer?: PublicKey
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
 * Falcon, `sha256(wire_pubkey)`).
 */
function vectorDigest(
  targetIx: TransactionInstruction,
  targetIndex: number,
  sigLen: number,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): Uint8Array {
  const allIxs = [...preInstructions, targetIx, ...postInstructions];
  const promoted = promoteToMessageFlags(allIxs, feePayer);
  const buffer = constructInstructionsData(promoted);

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

export function advanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): Uint8Array {
  const sigLen = scheme.signatureLen;
  const placeholder = new Uint8Array(sigLen);
  const advanceIx = createAdvanceInstruction(
    scheme,
    identity,
    placeholder,
    subInstructions
  );
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
