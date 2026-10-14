/**
 * What a vector account signs: a digest of the transaction, which the program
 * recomputes from the instructions sysvar.
 */
import { createHash } from "crypto";
import { Address, TransactionInstruction } from "@solana/web3.js";

import { Scheme, findVectorPda, readU16LE, writeU16LE } from "./scheme.js";
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

/**
 * One signer of an `advance`: its account, and for a scheme whose key
 * rotates (Winternitz, XMSS), the key that signs next.
 */
export type AdvanceSigner = { scheme: Scheme; identity: Uint8Array; nextKey?: Uint8Array };

/**
 * The message every signer of one advance approves: the SHA-256 of the
 * instructions sysvar without the advance's signatures.
 *
 * The advance goes after `preInstructions`. A passthrough is one of the pre
 * or post instructions, so the message covers it. `feePayer` only matters
 * when it is also an account of one of the instructions.
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
  // u16 data_len + data. The signatures are the end of the data.
  const offset = readU16LE(buffer, 2 + 2 * advanceIndex);
  const dataEnd = offset + 2 + 33 * advanceIx.keys.length + 32 + 2 + advanceIx.data.length;
  const signaturesLen = signers.reduce((n, s) => n + s.scheme.signatureLen, 0);

  const h = createHash("sha256");
  h.update(buffer.subarray(0, dataEnd - signaturesLen));
  h.update(buffer.subarray(dataEnd));
  return new Uint8Array(h.digest());
}

/**
 * What one signer signs, and the account's next nonce: `SHA256(message ||
 * nonce || vector)`, with `message` from {@link advanceMessage} and `vector`
 * the signer's account address.
 */
export function signerDigest(
  message: Uint8Array,
  nonce: Uint8Array,
  vector: Address
): Uint8Array {
  const h = createHash("sha256");
  h.update(message);
  h.update(nonce);
  h.update(vector.toBytes());
  return new Uint8Array(h.digest());
}

/** {@link signerDigest} for an advance with one signer, whose key never changes. */
export function advanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  return rotatingAdvanceVectorDigest(
    scheme,
    nonce,
    identity,
    new Uint8Array(),
    preInstructions,
    postInstructions,
    feePayer
  );
}

/**
 * {@link advanceVectorDigest} for Winternitz and XMSS, whose key rotates.
 * `nextKey` is the key that signs next: a Winternitz key must change every
 * time, an XMSS key may stay until its tree runs out. `identity` stays the
 * first key.
 */
export function rotatingAdvanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  nextKey: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: Address
): Uint8Array {
  const message = advanceMessage(
    [{ scheme, identity, nextKey }],
    preInstructions,
    postInstructions,
    feePayer
  );
  return signerDigest(message, nonce, findVectorPda(scheme, identity)[0]);
}

/**
 * The digest of an advance with nothing around it. Landing that advance only
 * moves the nonce, which cancels everything signed against the old one. It
 * must be the only instruction of its transaction.
 */
export function revocationDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array
): Uint8Array {
  return advanceVectorDigest(scheme, nonce, identity, [], []);
}
