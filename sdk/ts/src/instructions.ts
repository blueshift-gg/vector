/**
 * Instruction builders for every scheme. Each scheme's own helpers, such as
 * `createInitializeEd25519`, are in `./schemes/*`.
 */
import {
  Address,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";

import {
  Scheme,
  findVectorPda,
  writeU16LE,
  writeU64LE,
  PROGRAM_ID,
  INITIALIZE_DISCRIMINATOR,
  ADVANCE_DISCRIMINATOR,
  CLOSE_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
  WITHDRAW_DISCRIMINATOR,
} from "./scheme.js";

// ── Initialize ───────────────────────────────────────────────────────

/**
 * Build an `initialize` instruction for `identity`, the key the account is
 * created with.
 *
 * Accounts: `[payer, vector_pda, system_program]`.
 * Data: `[INITIALIZE_DISCRIMINATOR, scheme, ...identity]`.
 */
export function createInitializeInstruction(
  payer: Address,
  scheme: Scheme,
  identity: Uint8Array
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);

  const data = new Uint8Array(2 + identity.length);
  data[0] = INITIALIZE_DISCRIMINATOR;
  data[1] = scheme.id;
  data.set(identity, 2);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

// ── Advance ──────────────────────────────────────────────────────────

/**
 * Build an `advance` for one signer. It verifies the signature and moves the
 * nonce; pair it with {@link createPassthroughInstruction} to act.
 */
export function createAdvanceInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  advanceVectorSignature: Uint8Array
): TransactionInstruction {
  return createMultiAdvanceInstruction([
    { scheme, identity, signature: advanceVectorSignature },
  ]);
}

/**
 * Build an `advance` instruction for several signers. Every signer signs
 * its own `signerDigest` of the one `advanceMessage`.
 *
 * Accounts: `[vector_pda(writable)..., instructions_sysvar]`.
 * Data: `[ADVANCE_DISCRIMINATOR, signature...]`.
 */
export function createMultiAdvanceInstruction(
  signers: { scheme: Scheme; identity: Uint8Array; signature: Uint8Array }[]
): TransactionInstruction {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      ...signers.map(({ scheme, identity }) => ({
        pubkey: findVectorPda(scheme, identity)[0],
        isSigner: false,
        isWritable: true,
      })),
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      Uint8Array.of(ADVANCE_DISCRIMINATOR),
      ...signers.map((s) => s.signature),
    ]),
  });
}

// ── Passthrough ──────────────────────────────────────────────────────

/**
 * Build a `passthrough`: run `subInstructions` as the vector account, which
 * signs each of them. It needs an `advance` for the same account earlier in
 * the transaction. That advance's signature covers the whole transaction, so
 * there is no second signature here.
 */
export function createPassthroughInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  if (scheme.nextKeyLen !== 0) {
    throw new Error(
      "This scheme's key rotates: use createRotatingPassthroughInstruction"
    );
  }
  return passthroughInstruction(scheme, identity, subInstructions);
}

/**
 * {@link createPassthroughInstruction} for Winternitz and XMSS, whose key
 * rotates. `nextPublicKey` is the key that signs the next transaction, and
 * the signature covers it. Persist that signer first. `identity` stays the
 * first key.
 *
 * A Winternitz key signs once, so it must be replaced every time. An XMSS key
 * may be kept with `null` until its tree runs out.
 */
export function createRotatingPassthroughInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  nextPublicKey: Uint8Array | null,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  if (scheme.nextKeyLen === 0) {
    throw new Error("This scheme's key does not rotate");
  }
  if (nextPublicKey === null && !scheme.nextKeyOptional) {
    throw new Error("This scheme's key signs once");
  }
  if (nextPublicKey !== null && nextPublicKey.length !== scheme.nextKeyLen) {
    throw new Error(`Next key must be ${scheme.nextKeyLen} bytes`);
  }
  const ix = passthroughInstruction(scheme, identity, subInstructions);
  return new TransactionInstruction({
    programId: ix.programId,
    keys: ix.keys,
    data: Buffer.concat([
      ix.data.subarray(0, 1),
      scheme.nextKeyOptional ? Uint8Array.of(nextPublicKey ? 1 : 0) : new Uint8Array(),
      nextPublicKey ?? new Uint8Array(),
      ix.data.subarray(1),
    ]),
  });
}

function passthroughInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  if (subInstructions.length > 255) {
    throw new Error(
      `Too many sub-instructions: ${subInstructions.length} (max 255)`
    );
  }

  const [vectorPda] = findVectorPda(scheme, identity);

  const keys = [
    { pubkey: vectorPda, isSigner: false, isWritable: true },
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
  ];
  for (const ix of subInstructions) {
    keys.push({ pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const meta of ix.keys) {
      // Only the PDA receives its signer privilege during CPI.
      keys.push({
        pubkey: meta.pubkey,
        isSigner: meta.isSigner && !meta.pubkey.equals(vectorPda),
        isWritable: meta.isWritable,
      });
    }
  }

  // [disc(1)][num_ixs(u8)][per ix: num_accounts(u8) data_len(u16 LE) data]
  let dataLen = 1 + 1;
  for (const ix of subInstructions) {
    dataLen += 1 + 2 + ix.data.length;
  }

  const data = new Uint8Array(dataLen);
  let off = 0;

  data[off++] = PASSTHROUGH_DISCRIMINATOR;
  data[off++] = subInstructions.length;

  for (const ix of subInstructions) {
    if (ix.keys.length > 255) {
      throw new Error(
        `Sub-instruction has too many accounts: ${ix.keys.length} (max 255)`
      );
    }
    if (ix.data.length > 65535) {
      throw new Error(
        `Sub-instruction data too long: ${ix.data.length} (max 65535)`
      );
    }
    data[off++] = ix.keys.length;
    writeU16LE(data, ix.data.length, off);
    off += 2;
    data.set(ix.data, off);
    off += ix.data.length;
  }

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys,
    data: Buffer.from(data),
  });
}

// ── Close / Withdraw subinstructions ──────────────────────────────────

/**
 * Build a `close` to run inside a `passthrough`. On its own it fails: only a
 * passthrough makes the vector account a signer.
 */
export function createCloseSubinstruction(
  scheme: Scheme,
  identity: Uint8Array,
  closeTo: Address
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: closeTo, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([CLOSE_DISCRIMINATOR]),
  });
}

/**
 * Build a `withdraw` to run inside a `passthrough`, like {@link
 * createCloseSubinstruction}.
 */
export function createWithdrawSubinstruction(
  scheme: Scheme,
  identity: Uint8Array,
  receiver: Address,
  lamports: bigint
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);
  const data = new Uint8Array(1 + 8);
  data[0] = WITHDRAW_DISCRIMINATOR;
  writeU64LE(data, lamports, 1);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: receiver, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(data),
  });
}

// ── Instructions Sysvar Buffer ───────────────────────────────────────

/**
 * Serialize instructions into the instructions sysvar wire format.
 * Mirrors `solana_instructions_sysvar::construct_instructions_data`.
 */
export function constructInstructionsData(
  instructions: TransactionInstruction[]
): Uint8Array {
  const numIxs = instructions.length;

  let totalSize = 2 + 2 * numIxs;
  for (const ix of instructions) {
    totalSize += 2 + 33 * ix.keys.length + 32 + 2 + ix.data.length;
  }
  totalSize += 2; // footer

  const buf = new Uint8Array(totalSize);
  let off = 0;

  writeU16LE(buf, numIxs, off);
  off += 2;

  const offsetsStart = off;
  off += 2 * numIxs;

  for (let i = 0; i < numIxs; i++) {
    const ix = instructions[i];

    writeU16LE(buf, off, offsetsStart + 2 * i);

    writeU16LE(buf, ix.keys.length, off);
    off += 2;

    for (const meta of ix.keys) {
      let flags = 0;
      if (meta.isSigner) flags |= 0x01;
      if (meta.isWritable) flags |= 0x02;
      buf[off++] = flags;
      buf.set(meta.pubkey.toBytes(), off);
      off += 32;
    }

    buf.set(ix.programId.toBytes(), off);
    off += 32;

    writeU16LE(buf, ix.data.length, off);
    off += 2;

    buf.set(ix.data, off);
    off += ix.data.length;
  }

  // current_instruction_index = 0
  writeU16LE(buf, 0, off);

  return buf;
}
