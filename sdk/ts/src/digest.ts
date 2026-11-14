/**
 * What a vector account signs: a digest of the transaction, which the program
 * recomputes from the instructions sysvar.
 */
import { PublicKey, TransactionInstruction } from "@solana/web3.js";

import { NEVER_EXPIRES, readU16LE, sha256, VALID_UNTIL_LEN, writeU16LE } from "./bytes.js";
import { Scheme, findVectorPda } from "./scheme.js";
import {
  createMultiAdvanceInstruction,
  constructInstructionsData,
} from "./instructions.js";

export { NEVER_EXPIRES };

/**
 * What every signature starts with: a key signs `vector:` and then the
 * digest, never the digest alone, so a signature made for some other purpose
 * over 32 bytes (a login challenge, say) is not an authorization.
 */
export const SIGNED_PREFIX = new TextEncoder().encode("vector:");

/**
 * What a key signs for `digest`: `"vector:" || digest`, 39 bytes. Ed25519,
 * Falcon-512 and ML-DSA-44 sign it as is, secp256k1 signs its SHA-256, EIP-191
 * signs it as the `personal_sign` message, and Winternitz and XMSS, which sign
 * 32 bytes, sign its SHA-256 ({@link signedDigest}).
 */
export function signedMessage(digest: Uint8Array): Uint8Array {
  const message = new Uint8Array(SIGNED_PREFIX.length + digest.length);
  message.set(SIGNED_PREFIX);
  message.set(digest, SIGNED_PREFIX.length);
  return message;
}

/** `SHA256("vector:" || digest)`: what a scheme that signs 32 bytes signs. */
export function signedDigest(digest: Uint8Array): Uint8Array {
  return sha256(signedMessage(digest));
}

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
 * One signer of an `advance`: its account, the nonce account it signs over if
 * not its own nonce, for a scheme whose key rotates (Winternitz, XMSS) the key
 * that signs next. The expiry is the advance's, not a signer's.
 */
export type AdvanceSigner = {
  scheme: Scheme;
  identity: Uint8Array;
  nonceAccount?: PublicKey;
  nextKey?: Uint8Array;
};

/**
 * The message every signer of one advance approves: the SHA-256 of the
 * instructions sysvar without the advance's next keys and signatures. Its
 * `validUntil` (the last slot the transaction may land in; default never
 * expires) stays in, so every signature covers the one expiry.
 *
 * The advance goes after `preInstructions`. A passthrough is one of the pre
 * or post instructions, so the message covers it. `feePayer` only matters
 * when it is also an account of one of the instructions.
 */
export function advanceMessage(
  signers: AdvanceSigner[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey,
  validUntil?: bigint | number
): Uint8Array {
  const advanceIx = createMultiAdvanceInstruction(
    signers.map((signer) => ({
      ...signer,
      signature: new Uint8Array(signer.scheme.signatureLen),
    })),
    validUntil
  );
  return transactionMessage(
    [...preInstructions, advanceIx, ...postInstructions],
    preInstructions.length,
    feePayer
  );
}

/**
 * {@link advanceMessage} of a whole transaction: `instructions` as the
 * runtime puts them in the instructions sysvar, with the `advance` at
 * `advanceIndex`. Only the advance's data after its discriminator and
 * `validUntil` is cut, and only its length matters, so the signatures in it
 * may be real.
 */
export function transactionMessage(
  instructions: TransactionInstruction[],
  advanceIndex: number,
  feePayer?: PublicKey
): Uint8Array {
  const advanceIx = instructions[advanceIndex];
  const buffer = constructInstructionsData(promoteToMessageFlags(instructions, feePayer));
  // The runtime sets the footer to the executing instruction's index.
  writeU16LE(buffer, advanceIndex, buffer.length - 2);

  // Region: num_accounts (u16) + 33 * N metas + 32-byte program id +
  // u16 data_len + data. Everything after the discriminator and the
  // 8-byte `validUntil` is cut.
  const offset = readU16LE(buffer, 2 + 2 * advanceIndex);
  const dataEnd = offset + 2 + 33 * advanceIx.keys.length + 32 + 2 + advanceIx.data.length;
  const cut = advanceIx.data.length - 1 - VALID_UNTIL_LEN;

  return sha256(buffer.subarray(0, dataEnd - cut), buffer.subarray(dataEnd));
}

/**
 * What one signer's key signs (after {@link signedMessage}), and the
 * account's next nonce: `SHA256(message || nonce || vector || nextKey)`, with
 * `message` from {@link advanceMessage} (which covers the expiry), `nonce` the
 * one it signs over (for a nonce account, {@link signedNonce}), `vector` the
 * signer's account address and `nextKey` its {@link AdvanceSigner} `nextKey`.
 */
export function signerDigest(
  message: Uint8Array,
  nonce: Uint8Array,
  vector: PublicKey,
  { nextKey = new Uint8Array() }: { nextKey?: Uint8Array } = {}
): Uint8Array {
  return sha256(message, nonce, vector.toBytes(), nextKey);
}

/** {@link signerDigest} for an advance with one signer, whose key never changes. */
export function advanceVectorDigest(
  scheme: Scheme,
  nonce: Uint8Array,
  identity: Uint8Array,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey,
  validUntil?: bigint | number
): Uint8Array {
  return rotatingAdvanceVectorDigest(
    scheme,
    nonce,
    identity,
    new Uint8Array(),
    preInstructions,
    postInstructions,
    feePayer,
    validUntil
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
  feePayer?: PublicKey,
  validUntil?: bigint | number
): Uint8Array {
  const message = advanceMessage(
    [{ scheme, identity, nextKey }],
    preInstructions,
    postInstructions,
    feePayer,
    validUntil
  );
  return signerDigest(message, nonce, findVectorPda(scheme, identity)[0], { nextKey });
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
