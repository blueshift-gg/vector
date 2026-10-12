/**
 * The scheme/program/account primitives shared by every scheme: the
 * {@link Scheme} descriptor, the host-side {@link VectorAccount} header
 * mirror, canonical PDA derivation, and the shared low-level byte helpers.
 * Per-scheme details (identity derivation, signing, init builders) live in
 * `./schemes/*`.
 *
 * Mirrors `crates/core/src/scheme.rs`.
 */
import { createHash } from "crypto";
import { Connection, Address } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519.js";

// ── Constants ────────────────────────────────────────────────────────

export const INITIALIZE_DISCRIMINATOR = 0;
export const ADVANCE_DISCRIMINATOR = 1;
export const CLOSE_DISCRIMINATOR = 2;
export const WITHDRAW_DISCRIMINATOR = 3;
export const PASSTHROUGH_DISCRIMINATOR = 4;

/** The Vector program: one program for every signing scheme. */
export const PROGRAM_ID = new Address("vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV");

/**
 * Fixed-size account header: `nonce[32] || seed[32] || scheme[1] || bump[1]`.
 * The seed is the SHA-256 of the key the account was created with; the scheme
 * byte says which signing scheme the account belongs to. The scheme's
 * identity bytes follow the header.
 */
export const VECTOR_HEADER_LEN = 66;
export const VECTOR_PDA_SEED = new TextEncoder().encode("vector");

// Falcon-512 wire sizes — mirror `solana-falcon512` constants.
export const FALCON_PUBKEY_LEN = 897;
export const FALCON_SIGNATURE_LEN = 666;
export const FALCON_PREPARED_PUBKEY_LEN = 1024;

// ML-DSA-44 sizes — mirror `solana-ml-dsa` constants (FIPS 204 Table 2).
export const MLDSA44_PUBKEY_LEN = 1312;
export const MLDSA44_SIGNATURE_LEN = 2420;
export const MLDSA44_PREPARED_KEY_LEN = 20544;

/** sec1-compressed secp256k1 public key length. */
export const SECP256K1_COMPRESSED_PUBKEY_LEN = 33;

// ── Schemes ──────────────────────────────────────────────────────────

/**
 * Everything a client needs to use one signing scheme. Mirrors the `Scheme` struct in the Rust
 * `vector-core` crate.
 */
export interface Scheme {
  /**
   * The scheme byte: the second header field of every account, a PDA
   * seed, and what `initialize` takes after its discriminator.
   */
  id: number;
  /** Wire signature length carried in `advance` instruction data. */
  signatureLen: number;
  /**
   * Client identity length — the bytes hashed into the advance digest and
   * used to derive the PDA. The pubkey/address itself for most schemes; for
   * Falcon it's `sha256(wire_pubkey)` (32). Winternitz/XMSS keep
   * `sha256(initial_pubkey)` across rotations.
   */
  identityLen: number;
  /**
   * Bytes the on-chain account stores after the 34-byte header. Equals
   * `identityLen` for verbatim-pubkey schemes; larger for Falcon (32 + 1024
   * prepared).
   */
  storedIdentityLen: number;
  /**
   * Length of the key a `passthrough` carries for a scheme whose key
   * rotates (Winternitz, XMSS): the key that signs next. Zero otherwise.
   */
  nextKeyLen: number;
  /** The next key may be left out, keeping the current one (XMSS). */
  nextKeyOptional: boolean;
}

/** Total on-chain account size for a scheme. */
export function vectorAccountLen(scheme: Scheme): number {
  return VECTOR_HEADER_LEN + scheme.storedIdentityLen;
}

// ── VectorAccount ────────────────────────────────────────────────────

/** Header of a vector account. Scheme identity follows at offset 66. */
export interface VectorAccount {
  nonce: Uint8Array; // 32 bytes
  seed: Uint8Array; // 32 bytes
  scheme: number; // 1 byte
  bump: number; // 1 byte
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
  };
}

export function serializeVectorAccountHeader(account: VectorAccount): Uint8Array {
  const buf = new Uint8Array(VECTOR_HEADER_LEN);
  buf.set(account.nonce, 0);
  buf.set(account.seed, 32);
  buf[64] = account.scheme;
  buf[65] = account.bump;
  return buf;
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

const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");

/**
 * Synchronous PDA derivation — `@solana/web3.js@3` only ships the async
 * `Address.findProgramAddress`, but our SDK builders need to derive PDAs
 * inline without forcing every caller to be async. The algorithm mirrors
 * the on-chain `find_program_address`: walk bumps 255→0, accept the first
 * `sha256(seeds || bump || program_id || "ProgramDerivedAddress")` that
 * is *off* the ed25519 curve.
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
