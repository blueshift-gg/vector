/**
 * Generic, scheme-independent instruction builders. Per-scheme convenience
 * wrappers (e.g. `createInitializeEd25519`) live in `./schemes/*`.
 *
 * Mirrors `crates/core/src/instructions.rs`.
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
  INITIALIZE_DISCRIMINATOR,
  ADVANCE_DISCRIMINATOR,
  CLOSE_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
  WITHDRAW_DISCRIMINATOR,
} from "./scheme.js";

// ── Initialize ───────────────────────────────────────────────────────

/**
 * Build an `initialize` instruction. `initPayload` shape is scheme-defined;
 * there is no scheme byte (the program ID identifies the scheme).
 *
 * Accounts: `[payer, vector_pda, system_program]`.
 * Data: `[INITIALIZE_DISCRIMINATOR, ...initPayload]`.
 */
export function createInitializeInstruction(
  payer: Address,
  scheme: Scheme,
  identity: Uint8Array,
  initPayload: Uint8Array
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);

  const data = new Uint8Array(1 + initPayload.length);
  data[0] = INITIALIZE_DISCRIMINATOR;
  data.set(initPayload, 1);

  return new TransactionInstruction({
    programId: scheme.programId,
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
 * Build an `advance` instruction — verifies the signature and installs the
 * digest as the next nonce. No CPI passthrough: pair this with
 * {@link createPassthroughInstruction} in the same tx if you need to
 * authorise CPIs under the vector PDA's signer seeds.
 *
 * Accounts: `[vector_pda(writable), instructions_sysvar]`.
 * Data: `[ADVANCE_DISCRIMINATOR, ...signature]`.
 */
export function createAdvanceInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  advanceVectorSignature: Uint8Array
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);

  const sigLen = advanceVectorSignature.length;
  const data = new Uint8Array(1 + sigLen);
  data[0] = ADVANCE_DISCRIMINATOR;
  data.set(advanceVectorSignature, 1);

  return new TransactionInstruction({
    programId: scheme.programId,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}

// ── Passthrough ──────────────────────────────────────────────────────

/**
 * Build a `passthrough` instruction — replays a batch of CPIs under the
 * vector PDA's signer seeds. Must be paired with a sibling `advance` ix
 * earlier in the same tx: the on-chain handler scans the instructions
 * sysvar and refuses if it can't find a prior `advance` for the same
 * vector PDA. The sibling advance's signature digest commits to the
 * entire sysvar buffer (minus its sig bytes), so the passthrough's data
 * and account layout are authenticated end-to-end without a second
 * signature here.
 *
 * Accounts: `[vector_pda(writable), instructions_sysvar, sub_ix_program,
 * ...sub_ix accounts...]` repeated per sub-instruction.
 * Data: `[PASSTHROUGH_DISCRIMINATOR, num_ixs(u8),
 * {num_accounts(u8), data_len(u16 LE), data}...]`.
 */
export function createPassthroughInstruction(
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
      // Clear isSigner: PDA signing comes from invoke_signed during CPI,
      // not from transaction-level signatures.
      keys.push({
        pubkey: meta.pubkey,
        isSigner: false,
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
    programId: scheme.programId,
    keys,
    data: Buffer.from(data),
  });
}

// ── Close / Withdraw subinstructions ──────────────────────────────────

/**
 * Build a `close` sub-instruction for use inside a `passthrough` ix. Direct
 * top-level invocation fails the `vector.is_signer()` gate; close is only
 * reachable as a CPI from passthrough (which promotes the vector PDA to a
 * signer via `invoke_signed`).
 *
 * Accounts: `[vector_pda, close_to]`. Data: `[CLOSE_DISCRIMINATOR]`.
 */
export function createCloseSubinstruction(
  scheme: Scheme,
  identity: Uint8Array,
  closeTo: Address
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);
  return new TransactionInstruction({
    programId: scheme.programId,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: closeTo, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([CLOSE_DISCRIMINATOR]),
  });
}

/**
 * Build a `withdraw` sub-instruction. Same authorisation model as
 * {@link createCloseSubinstruction}.
 *
 * Accounts: `[vector_pda, receiver]`.
 * Data: `[WITHDRAW_DISCRIMINATOR, lamports: u64 LE]`.
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
    programId: scheme.programId,
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
