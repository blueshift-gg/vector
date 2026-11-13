/**
 * Instruction builders for every scheme. Each scheme's own helpers, such as
 * `createInitializeEd25519`, are in `./schemes/*`.
 */
import {
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";

import { concatBytes, validUntilBytes, writeU16LE, writeU64LE } from "./bytes.js";
import {
  Scheme,
  findSystemPda,
  findVectorPda,
  vectorAccountLen,
  PROGRAM_ID,
  MAX_PERMITTED_DATA_INCREASE,
  INITIALIZE_DISCRIMINATOR,
  ADVANCE_DISCRIMINATOR,
  CLOSE_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
  WITHDRAW_DISCRIMINATOR,
  INITIALIZE_NONCE_DISCRIMINATOR,
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
  payer: PublicKey,
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
    data,
  });
}

/**
 * Every `initialize` that creates the account for `identity`: the first
 * carries the key, and each later one grows the account by what one
 * instruction can allocate until it is complete. One instruction for every
 * scheme but ML-DSA-44, which takes three. They fit one transaction.
 */
export function createInitializeInstructions(
  payer: PublicKey,
  scheme: Scheme,
  identity: Uint8Array
): TransactionInstruction[] {
  const first = createInitializeInstruction(payer, scheme, identity);
  const calls = Math.ceil(vectorAccountLen(scheme) / MAX_PERMITTED_DATA_INCREASE);
  const grow = () =>
    new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: first.keys,
      data: Uint8Array.of(INITIALIZE_DISCRIMINATOR),
    });
  return [first, ...Array.from({ length: calls - 1 }, grow)];
}

// ── Advance ──────────────────────────────────────────────────────────

/**
 * Build an `advance` for one signer, whose key never changes. It verifies the
 * signature and moves the nonce; pair it with {@link
 * createPassthroughInstruction} to act.
 */
export function createAdvanceInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  advanceVectorSignature: Uint8Array,
  validUntil?: bigint | number
): TransactionInstruction {
  return createMultiAdvanceInstruction(
    [{ scheme, identity, signature: advanceVectorSignature }],
    validUntil
  );
}

/**
 * {@link createAdvanceInstruction} for Winternitz and XMSS, whose key rotates:
 * `nextKey` is the key that signs next, and the signature covers it (see
 * `rotatingAdvanceVectorDigest`). Persist that signer before authorizing this
 * instruction.
 */
export function createRotatingAdvanceInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  nextKey: Uint8Array,
  advanceVectorSignature: Uint8Array,
  validUntil?: bigint | number
): TransactionInstruction {
  return createMultiAdvanceInstruction(
    [{ scheme, identity, nextKey, signature: advanceVectorSignature }],
    validUntil
  );
}

/**
 * Build an `advance` instruction for several signers. Every signer signs
 * its own `signerDigest` of the one `advanceMessage`.
 *
 * Accounts: `[{vector_pda(writable), nonceAccount(writable)?}..., instructions_sysvar]`.
 * A signer with a `nonceAccount` signs over that account's nonce.
 * Data: `[ADVANCE_DISCRIMINATOR, validUntil(u64 LE), {nextKey, signature}...]`.
 * `validUntil` is the last slot the transaction may land in, for every
 * signer: the message covers it, so no one can extend it alone. The default
 * never expires.
 */
export function createMultiAdvanceInstruction(
  signers: {
    scheme: Scheme;
    identity: Uint8Array;
    nonceAccount?: PublicKey;
    nextKey?: Uint8Array;
    signature: Uint8Array;
  }[],
  validUntil?: bigint | number
): TransactionInstruction {
  if (signers.length === 0) throw new Error("An advance needs at least one signer");
  const entries = signers.map(({ scheme, nextKey = new Uint8Array(), signature }) => {
    if (nextKey.length !== scheme.nextKeyLen) {
      throw new Error(`Next key must be ${scheme.nextKeyLen} bytes`);
    }
    // No lengths are in the data, so a wrong one shifts every later signer.
    if (signature.length !== scheme.signatureLen) {
      throw new Error(`Signature must be ${scheme.signatureLen} bytes, got ${signature.length}`);
    }
    return concatBytes(nextKey, signature);
  });
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      ...signers.flatMap(({ scheme, identity, nonceAccount }) =>
        [findVectorPda(scheme, identity)[0], ...(nonceAccount ? [nonceAccount] : [])].map(
          (pubkey) => ({ pubkey, isSigner: false, isWritable: true })
        )
      ),
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ],
    data: concatBytes(Uint8Array.of(ADVANCE_DISCRIMINATOR), validUntilBytes(validUntil), ...entries),
  });
}

// ── Passthrough ──────────────────────────────────────────────────────

/** Most signers one `passthrough` takes: the runtime's limit on signers of one call. */
export const MAX_PASSTHROUGH_SIGNERS = 16;

/**
 * Who a passthrough signs as: a vector account, or with `system` its system
 * PDA ({@link findSystemPda}) for what only a system account can do, such as
 * a System `Transfer`.
 */
export type PassthroughSigner = { scheme: Scheme; identity: Uint8Array; system?: boolean };

/**
 * Build a `passthrough`: run `subInstructions` as the vector account, which
 * signs each of them. It needs an `advance` listing the same account earlier
 * in the transaction. That advance's signature covers the whole transaction,
 * so there is no second signature here.
 */
export function createPassthroughInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  return createMultiPassthroughInstruction([{ scheme, identity }], subInstructions);
}

/**
 * {@link createPassthroughInstruction}, signing as the account's system PDA
 * instead of the account.
 */
export function createSystemPassthroughInstruction(
  scheme: Scheme,
  identity: Uint8Array,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  return createMultiPassthroughInstruction(
    [{ scheme, identity, system: true }],
    subInstructions
  );
}

/**
 * Build a `passthrough` for several signers, each a vector account or its
 * system PDA. The transaction's first `advance` must come earlier and list
 * every one of the accounts.
 *
 * Accounts: `[instructions_sysvar, vector_pda..., sub_ix_program, ...sub_ix
 * accounts...]`. Data: `[disc, num_signers(u8), system(u8)..., num_ixs(u8),
 * {num_accounts(u8), data_len(u16 LE), data}...]`.
 */
export function createMultiPassthroughInstruction(
  signers: PassthroughSigner[],
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  if (signers.length === 0 || signers.length > MAX_PASSTHROUGH_SIGNERS) {
    throw new Error(
      `A passthrough takes 1 to ${MAX_PASSTHROUGH_SIGNERS} signers, got ${signers.length}`
    );
  }
  if (subInstructions.length > 255) {
    throw new Error(
      `Too many sub-instructions: ${subInstructions.length} (max 255)`
    );
  }

  const keys = [
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
  ];
  const addresses: PublicKey[] = [];
  for (const { scheme, identity, system = false } of signers) {
    const [vectorPda] = findVectorPda(scheme, identity);
    keys.push({ pubkey: vectorPda, isSigner: false, isWritable: false });
    addresses.push(system ? findSystemPda(vectorPda)[0] : vectorPda);
  }

  for (const ix of subInstructions) {
    keys.push({ pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const meta of ix.keys) {
      // The program gives the signers their signature during CPI.
      keys.push({
        pubkey: meta.pubkey,
        isSigner: meta.isSigner && !addresses.some((a) => a.equals(meta.pubkey)),
        isWritable: meta.isWritable,
      });
    }
  }

  const header = Uint8Array.of(
    PASSTHROUGH_DISCRIMINATOR,
    signers.length,
    ...signers.map(({ system = false }) => Number(system)),
    subInstructions.length
  );
  let dataLen = header.length;
  for (const ix of subInstructions) {
    dataLen += 1 + 2 + ix.data.length;
  }

  const data = new Uint8Array(dataLen);
  data.set(header);
  let off = header.length;

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
    data,
  });
}

// ── Nonce accounts ───────────────────────────────────────────────────

/**
 * Build an `initializeNonce`: make `nonceAccount` a nonce account of `vector`.
 * It signs from the next slot. Put it after the System `createAccount` that
 * creates the account, assigned to the program with `NONCE_ACCOUNT_LEN`
 * bytes; the nonce account signs both.
 *
 * Accounts: `[nonceAccount(signer, writable), vector]`.
 * Data: `[INITIALIZE_NONCE_DISCRIMINATOR]`.
 */
export function createInitializeNonceInstruction(
  nonceAccount: PublicKey,
  vector: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: nonceAccount, isSigner: true, isWritable: true },
      { pubkey: vector, isSigner: false, isWritable: false },
    ],
    data: Uint8Array.of(INITIALIZE_NONCE_DISCRIMINATOR),
  });
}

// ── Close / Withdraw subinstructions ──────────────────────────────────

/**
 * Build a `close` to run inside a `passthrough`: of the vector account, or
 * with `nonceAccount` of that nonce account. On its own it fails: only a
 * passthrough makes the vector account a signer.
 */
export function createCloseSubinstruction(
  scheme: Scheme,
  identity: Uint8Array,
  closeTo: PublicKey,
  nonceAccount?: PublicKey
): TransactionInstruction {
  const [vectorPda] = findVectorPda(scheme, identity);
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      { pubkey: closeTo, isSigner: false, isWritable: true },
      ...(nonceAccount ? [{ pubkey: nonceAccount, isSigner: false, isWritable: true }] : []),
    ],
    data: Uint8Array.of(CLOSE_DISCRIMINATOR),
  });
}

/**
 * Build a `withdraw` to run inside a `passthrough`, like {@link
 * createCloseSubinstruction}.
 */
export function createWithdrawSubinstruction(
  scheme: Scheme,
  identity: Uint8Array,
  receiver: PublicKey,
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
    data,
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
