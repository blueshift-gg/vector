/**
 * What every scheme shares: the {@link Scheme} descriptor, the account
 * header, and PDA derivation.
 */
import { createHash } from "crypto";
import { Connection, Address } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";

// ── Constants ────────────────────────────────────────────────────────

export const ADVANCE_DISCRIMINATOR = 0;
export const PASSTHROUGH_DISCRIMINATOR = 1;
export const INITIALIZE_DISCRIMINATOR = 2;
export const WITHDRAW_DISCRIMINATOR = 3;
export const CLOSE_DISCRIMINATOR = 4;
export const INITIALIZE_NONCE_DISCRIMINATOR = 5;

/** The Vector program: one program for every signing scheme. */
export const PROGRAM_ID = new Address("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

/**
 * The account header: `nonce[32] || seed[32] || scheme[1] || bump[1] ||
 * system_bump[1] || pad[1]`. The seed is the SHA-256 of the key the account
 * was created with. The scheme's identity bytes follow.
 */
/**
 * The program's own errors, as `ProgramError::Custom(code)`; every other
 * failure is a standard `ProgramError`. Checked against the program by
 * `fixtures/program.json`.
 */
export enum VectorError {
  /** `advance` or `passthrough` ran inside another instruction. */
  NotTopLevel = 0,
  /** `passthrough`: no earlier `advance`, or the first one does not list a signer. */
  NotAdvanced = 1,
  /** Winternitz: the next key is the key that just signed. */
  KeyReused = 2,
  /** XMSS: the signature's leaf has signed before. */
  LeafUsed = 3,
  /** XMSS: the tree's last leaf signed, and the key was not replaced. */
  TreeExhausted = 4,
  /** `advance`, `close`: the nonce account belongs to another vector. */
  ForeignNonce = 5,
  /** `initializeNonce`: a Winternitz or XMSS vector signs over its own nonce only. */
  KeyRotates = 6,
  /** `advance`, `close`: the nonce account was created in this slot. */
  FreshNonce = 7,
}

export const VECTOR_HEADER_LEN = 68;
/** What one instruction can allocate; a bigger account takes more `initialize` calls. */
export const MAX_PERMITTED_DATA_INCREASE = 10_240;
export const VECTOR_PDA_SEED = new TextEncoder().encode("vector");
/** What a nonce account's first nonce hashes before its address. */
export const NONCE_TAG = new TextEncoder().encode("nonce");

// ── Schemes ──────────────────────────────────────────────────────────

/**
 * Everything a client needs to use one signing scheme. Mirrors the `Scheme` struct in the Rust
 * `vector-core` crate.
 */
export interface Scheme {
  /**
   * The scheme byte: a header field of every account, a PDA seed, and
   * what `initialize` takes after its discriminator.
   */
  id: number;
  /** Wire signature length carried in `advance` instruction data. */
  signatureLen: number;
  /**
   * Length of the identity: the key the account is created with, as
   * `initialize` takes it. It names the account for good, also after a
   * Winternitz or XMSS key rotates.
   */
  identityLen: number;
  /**
   * Bytes the on-chain account stores after its header: the key in the
   * form the scheme verifies against. Equals `identityLen` for schemes that
   * store the key as given; Falcon-512 and ML-DSA-44 prepare it.
   */
  storedIdentityLen: number;
  /**
   * Length of the key an `advance` carries for a scheme whose key rotates
   * (Winternitz, XMSS): the key that signs next. Zero otherwise.
   */
  nextKeyLen: number;
}

/** Total on-chain account size for a scheme. */
export function vectorAccountLen(scheme: Scheme): number {
  return VECTOR_HEADER_LEN + scheme.storedIdentityLen;
}

// ── VectorAccount ────────────────────────────────────────────────────

/** Header of a vector account. Scheme identity follows at offset 68. */
export interface VectorAccount {
  nonce: Uint8Array; // 32 bytes
  seed: Uint8Array; // 32 bytes
  scheme: number; // 1 byte
  bump: number; // 1 byte
  systemBump: number; // 1 byte
}

export function deserializeVectorAccount(data: Uint8Array): VectorAccount {
  if (data.length < VECTOR_HEADER_LEN) {
    throw new Error(
      `VectorAccount data too short: ${data.length} < ${VECTOR_HEADER_LEN}`
    );
  }
  return {
    nonce: data.slice(0, 32),
    seed: data.slice(32, 64),
    scheme: data[64],
    bump: data[65],
    systemBump: data[66],
  };
}

// ── PDA ──────────────────────────────────────────────────────────────

/** sha256 helper returning a `Uint8Array`. */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** The PDA seed for an identity: its SHA-256, for every scheme. */
export function vectorSeed(identity: Uint8Array): Uint8Array {
  return sha256(identity);
}

/** Derive `(vector_pda, bump)`. Seeds: `["vector", [scheme], sha256(identity)]`. */
export function findVectorPda(
  scheme: Scheme,
  identity: Uint8Array
): [Address, number] {
  if (identity.length !== scheme.identityLen) {
    throw new Error(`Identity must be ${scheme.identityLen} bytes`);
  }
  return findProgramAddressSync(
    [VECTOR_PDA_SEED, Uint8Array.of(scheme.id), vectorSeed(identity)],
    PROGRAM_ID
  );
}

/**
 * Derive the vector account's system PDA, `[vector]`, and its bump. It
 * belongs to the System program; a passthrough can sign as it.
 */
export function findSystemPda(vector: Address): [Address, number] {
  return findProgramAddressSync([vector.toBytes()], PROGRAM_ID);
}

/**
 * What a signature over a nonce account is over, in place of a nonce:
 * `SHA256(nonce account's nonce || vector's own nonce)`. Moving the vector's
 * own nonce changes it for every nonce account of the vector.
 */
export function signedNonce(nonce: Uint8Array, vectorNonce: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(nonce).update(vectorNonce).digest());
}

/** A nonce account: `nonce[32] || vector[32] || created slot (u64 LE)`. */
export const NONCE_ACCOUNT_LEN = 72;
export class NonceAccount {
  constructor(
    /** The chain's current link; sign over {@link signedNonce} of it. */
    readonly nonce: Uint8Array,
    /** The vector account whose key signs over it. */
    readonly vector: Address,
    /** The slot it was created in. It signs and closes from the next. */
    readonly created: bigint
  ) {}

  /** Read a nonce account's data, as `@solana/web3.js`'s `NonceAccount`. */
  static fromAccountData(data: Uint8Array): NonceAccount {
    if (data.length !== NONCE_ACCOUNT_LEN) {
      throw new Error(`NonceAccount data must be ${NONCE_ACCOUNT_LEN} bytes, got ${data.length}`);
    }
    const created = new DataView(data.buffer, data.byteOffset).getBigUint64(64, true);
    return new NonceAccount(data.slice(0, 32), new Address(data.slice(32, 64)), created);
  }
}

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

/**
 * `@solana/web3.js` 3 only derives PDAs asynchronously, and the builders here
 * are synchronous. Same algorithm: try bumps from 255 down and take the first
 * hash that is off the ed25519 curve.
 */
function findProgramAddressSync(
  seeds: Uint8Array[],
  programId: Address
): [Address, number] {
  const programBytes = programId.toBytes();
  const totalLen =
    seeds.reduce((n, s) => n + s.length, 0) + 1 + programBytes.length + PDA_MARKER.length;
  const buf = new Uint8Array(totalLen);
  let off = 0;
  for (const s of seeds) {
    buf.set(s, off);
    off += s.length;
  }
  const bumpOffset = off;
  off += 1;
  buf.set(programBytes, off);
  off += programBytes.length;
  buf.set(PDA_MARKER, off);

  for (let bump = 255; bump >= 0; bump--) {
    buf[bumpOffset] = bump;
    const hash = sha256(buf);
    if (!isOnCurve(hash)) {
      return [new Address(hash), bump];
    }
  }
  throw new Error("Unable to find a viable PDA bump seed");
}

function isOnCurve(point: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(point);
    return true;
  } catch {
    return false;
  }
}

// ── Query ────────────────────────────────────────────────────────────

export async function fetchVectorAccount(
  connection: Connection,
  scheme: Scheme,
  identity: Uint8Array
): Promise<VectorAccount> {
  const [pda] = findVectorPda(scheme, identity);
  const info = await connection.getAccountInfo(pda);
  if (!info) {
    throw new Error("Vector account not found");
  }
  return deserializeVectorAccount(info.data);
}

export async function fetchNonceAccount(
  connection: Connection,
  nonceAccount: Address
): Promise<NonceAccount> {
  const info = await connection.getAccountInfo(nonceAccount);
  if (!info) {
    throw new Error("Nonce account not found");
  }
  return NonceAccount.fromAccountData(info.data);
}

// ── Helpers ──────────────────────────────────────────────────────────

export function writeU16LE(buf: Uint8Array, value: number, offset: number): void {
  buf[offset] = value & 0xff;
  buf[offset + 1] = (value >> 8) & 0xff;
}

export function readU16LE(buf: Uint8Array, offset: number): number {
  return buf[offset] | (buf[offset + 1] << 8);
}

export function writeU64LE(buf: Uint8Array, value: bigint, offset: number): void {
  for (let i = 0; i < 8; i++) {
    buf[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn);
  }
}
