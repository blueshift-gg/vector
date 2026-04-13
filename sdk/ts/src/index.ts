import {
  Connection,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519 } from "@noble/curves/ed25519";

// ── Constants ────────────────────────────────────────────────────────

export const VECTOR_PROGRAM_ID = new PublicKey(
  "vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV"
);

export const INITIALIZE_DISCRIMINATOR = 0;
export const ADVANCE_DISCRIMINATOR = 1;
export const CLOSE_DISCRIMINATOR = 2;

export const SIGNATURE_LEN = 64;
export const VECTOR_ACCOUNT_LEN = 65;
export const VECTOR_PDA_SEED = new TextEncoder().encode("vector");

// ── VectorAccount ────────────────────────────────────────────────────

export interface VectorAccount {
  seed: Uint8Array; // 32 bytes
  address: PublicKey;
  bump: number;
}

export function deserializeVectorAccount(data: Uint8Array): VectorAccount {
  if (data.length < VECTOR_ACCOUNT_LEN) {
    throw new Error(
      `VectorAccount data too short: ${data.length} < ${VECTOR_ACCOUNT_LEN}`
    );
  }
  return {
    seed: data.slice(0, 32),
    address: new PublicKey(data.slice(32, 64)),
    bump: data[64],
  };
}

export function serializeVectorAccount(account: VectorAccount): Uint8Array {
  const buf = new Uint8Array(VECTOR_ACCOUNT_LEN);
  buf.set(account.seed, 0);
  buf.set(account.address.toBytes(), 32);
  buf[64] = account.bump;
  return buf;
}

// ── PDA ──────────────────────────────────────────────────────────────

export function findVectorPda(address: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [VECTOR_PDA_SEED, address.toBytes()],
    VECTOR_PROGRAM_ID
  );
}

// ── Query ────────────────────────────────────────────────────────────

export async function fetchVectorAccount(
  connection: Connection,
  address: PublicKey
): Promise<VectorAccount> {
  const [pda] = findVectorPda(address);
  const info = await connection.getAccountInfo(pda);
  if (!info) {
    throw new Error(
      `Vector account not found for address ${address.toBase58()}`
    );
  }
  return deserializeVectorAccount(info.data);
}

// ── Instructions ─────────────────────────────────────────────────────

export function createInitializeInstruction(
  payer: PublicKey,
  address: PublicKey
): TransactionInstruction {
  const [vectorPda] = findVectorPda(address);

  const data = Buffer.alloc(1 + 32);
  data[0] = INITIALIZE_DISCRIMINATOR;
  data.set(address.toBytes(), 1);

  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      {
        pubkey: SystemProgram.programId,
        isSigner: false,
        isWritable: false,
      },
    ],
    data,
  });
}

export function createAdvanceInstruction(
  address: PublicKey,
  advanceVectorSignature: Uint8Array,
  subInstructions: TransactionInstruction[]
): TransactionInstruction {
  if (subInstructions.length > 255) {
    throw new Error(
      `Too many sub-instructions: ${subInstructions.length} (max 255)`
    );
  }

  const [vectorPda] = findVectorPda(address);

  const keys = [
    { pubkey: vectorPda, isSigner: false, isWritable: true },
    {
      pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
      isSigner: false,
      isWritable: false,
    },
  ];
  for (const ix of subInstructions) {
    keys.push({ pubkey: ix.programId, isSigner: false, isWritable: false });
    for (const meta of ix.keys) {
      // Clear isSigner: PDA signing comes from invoke_signed during CPI,
      // not from transaction-level signatures. Copying isSigner: true would
      // make the PDA a required transaction signer, which is impossible.
      keys.push({ pubkey: meta.pubkey, isSigner: false, isWritable: meta.isWritable });
    }
  }

  // [disc(1)][sig(64)][num_ixs(u8)][per ix: num_accounts(u8) data_len(u16 LE) data]
  let dataLen = 1 + SIGNATURE_LEN + 1;
  for (const ix of subInstructions) {
    dataLen += 1 + 2 + ix.data.length;
  }

  const data = Buffer.alloc(dataLen);
  let off = 0;

  data[off++] = ADVANCE_DISCRIMINATOR;
  data.set(advanceVectorSignature, off);
  off += SIGNATURE_LEN;
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
    programId: VECTOR_PROGRAM_ID,
    keys,
    data,
  });
}

export function createCloseInstruction(
  address: PublicKey,
  closeVectorSignature: Uint8Array,
  closeTo: PublicKey
): TransactionInstruction {
  const [vectorPda] = findVectorPda(address);

  const data = Buffer.alloc(1 + SIGNATURE_LEN);
  data[0] = CLOSE_DISCRIMINATOR;
  data.set(closeVectorSignature, 1);

  return new TransactionInstruction({
    programId: VECTOR_PROGRAM_ID,
    keys: [
      { pubkey: vectorPda, isSigner: false, isWritable: true },
      {
        pubkey: SYSVAR_INSTRUCTIONS_PUBKEY,
        isSigner: false,
        isWritable: false,
      },
      { pubkey: closeTo, isSigner: false, isWritable: true },
    ],
    data,
  });
}

// ── Instructions Sysvar Buffer ───────────────────────────────────────

/**
 * Serialize instructions into the instructions sysvar wire format.
 * Mirrors `solana_instructions_sysvar::construct_instructions_data`.
 *
 * Layout:
 *   [0..2]          num_instructions (u16 LE)
 *   [2..2+2*N]      offset per instruction (u16 LE each)
 *   [...]           instruction regions
 *   [len-2..len]    current_instruction_index (u16 LE, set to 0)
 *
 * Each instruction region:
 *   [0..2]          num_accounts (u16 LE)
 *   [2..2+33*A]     account metas (1 flag byte + 32 pubkey each)
 *   [+32]           program_id
 *   [+2]            data_len (u16 LE)
 *   [...]           data
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

// ── Digest ───────────────────────────────────────────────────────────

/**
 * Promote instruction-level account flags to message-level flags, matching
 * what the Solana runtime writes into the instructions sysvar.
 *
 * In a compiled transaction message:
 *   isSigner  = true if the account is the fee payer OR any instruction
 *               marks it as isSigner
 *   isWritable = true if the account is the fee payer OR any instruction
 *               marks it as isWritable
 *
 * The instructions sysvar uses these message-level flags for every occurrence
 * of an account across all instructions.
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
 * Shared digest: `SHA256(buffer[..sigStart] || seed || address || buffer[sigEnd..])`.
 * The signature hole is located after the 1-byte discriminator in the target
 * instruction's data region.
 */
function vectorDigest(
  targetIx: TransactionInstruction,
  targetIndex: number,
  seed: Uint8Array,
  address: PublicKey,
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
  const sigEnd = sigStart + SIGNATURE_LEN;

  const hasher = sha256.create();
  hasher.update(buffer.subarray(0, sigStart));
  hasher.update(seed);
  hasher.update(address.toBytes());
  hasher.update(buffer.subarray(sigEnd));
  return hasher.digest();
}

export function advanceVectorDigest(
  seed: Uint8Array,
  address: PublicKey,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): Uint8Array {
  const placeholder = new Uint8Array(SIGNATURE_LEN);
  const advanceIx = createAdvanceInstruction(
    address,
    placeholder,
    subInstructions
  );
  return vectorDigest(
    advanceIx,
    preInstructions.length,
    seed,
    address,
    preInstructions,
    postInstructions,
    feePayer
  );
}

export function closeVectorDigest(
  seed: Uint8Array,
  address: PublicKey,
  closeTo: PublicKey,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): Uint8Array {
  const placeholder = new Uint8Array(SIGNATURE_LEN);
  const closeIx = createCloseInstruction(address, placeholder, closeTo);
  return vectorDigest(
    closeIx,
    preInstructions.length,
    seed,
    address,
    preInstructions,
    postInstructions,
    feePayer
  );
}

// ── Sign ─────────────────────────────────────────────────────────────

/**
 * Sign the advance digest and return a ready-to-submit advance instruction.
 * @param signingKey 32-byte Ed25519 private key seed
 * @param feePayer The transaction fee payer (needed for correct sysvar flag promotion)
 */
export function signAdvanceInstruction(
  signingKey: Uint8Array,
  seed: Uint8Array,
  subInstructions: TransactionInstruction[],
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): TransactionInstruction {
  const address = new PublicKey(ed25519.getPublicKey(signingKey));
  const digest = advanceVectorDigest(
    seed,
    address,
    subInstructions,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = ed25519.sign(digest, signingKey);
  return createAdvanceInstruction(address, signature, subInstructions);
}

/**
 * Sign the close digest and return a ready-to-submit close instruction.
 * @param signingKey 32-byte Ed25519 private key seed
 * @param feePayer The transaction fee payer (needed for correct sysvar flag promotion)
 */
export function signCloseInstruction(
  signingKey: Uint8Array,
  seed: Uint8Array,
  closeTo: PublicKey,
  preInstructions: TransactionInstruction[],
  postInstructions: TransactionInstruction[],
  feePayer?: PublicKey
): TransactionInstruction {
  const address = new PublicKey(ed25519.getPublicKey(signingKey));
  const digest = closeVectorDigest(
    seed,
    address,
    closeTo,
    preInstructions,
    postInstructions,
    feePayer
  );
  const signature = ed25519.sign(digest, signingKey);
  return createCloseInstruction(address, signature, closeTo);
}

// ── Helpers ──────────────────────────────────────────────────────────

function writeU16LE(buf: Uint8Array, value: number, offset: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}
