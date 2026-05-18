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
import { Connection, PublicKey } from "@solana/web3.js";

// ── Constants ────────────────────────────────────────────────────────

export const INITIALIZE_DISCRIMINATOR = 0;
export const ADVANCE_DISCRIMINATOR = 1;
export const CLOSE_DISCRIMINATOR = 2;
export const WITHDRAW_DISCRIMINATOR = 3;

/**
 * Fixed-size account header: `nonce[32] || bump[1]`. Each scheme is its own
 * program, so there is no on-chain scheme discriminator; the program ID
 * identifies the scheme. The scheme's identity bytes follow the header.
 */
export const VECTOR_HEADER_LEN = 33;
export const VECTOR_PDA_SEED = new TextEncoder().encode("vector");

// Falcon-512 wire sizes — mirror `solana-falcon512` constants.
export const FALCON_PUBKEY_LEN = 897;
export const FALCON_SIGNATURE_LEN = 666;
export const FALCON_PREPARED_PUBKEY_LEN = 1024;

/** sec1-compressed secp256k1 public key length. */
export const SECP256K1_COMPRESSED_PUBKEY_LEN = 33;

// Hawk-512 wire sizes — mirror `solana-hawk512` constants.
export const HAWK_PUBKEY_LEN = 1024;
export const HAWK_SIGNATURE_LEN = 555;
export const HAWK_PREPARED_PUBKEY_LEN = 18464;

// ── Schemes ──────────────────────────────────────────────────────────

/**
 * Everything a client needs to address one Vector program. Each on-chain
 * scheme is a separate program. Mirrors the `Scheme` struct in the Rust
 * `vector-core` crate.
 */
export interface Scheme {
  /** On-chain program ID (matches the program's `declare_id!`). */
  programId: PublicKey;
  /** Wire signature length carried in `advance` instruction data. */
  signatureLen: number;
  /**
   * Client identity length — the bytes hashed into the advance digest and
   * used to derive the PDA. The pubkey/address itself for most schemes; for
   * Falcon it's `sha256(wire_pubkey)` (32).
   */
  identityLen: number;
  /**
   * Bytes the on-chain account stores after the 33-byte header. Equals
   * `identityLen` for verbatim-pubkey schemes; larger for Falcon (32 + 1
   * pad + 1024 prepared).
   */
  storedIdentityLen: number;
}

/** Total on-chain account size for a scheme. */
export function vectorAccountLen(scheme: Scheme): number {
  return VECTOR_HEADER_LEN + scheme.storedIdentityLen;
}

// ── VectorAccount ────────────────────────────────────────────────────

/** Header of a vector account. Scheme identity follows at offset 33. */
export interface VectorAccount {
  nonce: Uint8Array; // 32 bytes
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
    bump: data[32],
  };
}

export function serializeVectorAccountHeader(account: VectorAccount): Uint8Array {
  const buf = new Uint8Array(VECTOR_HEADER_LEN);
  buf.set(account.nonce, 0);
  buf[32] = account.bump;
  return buf;
}

// ── PDA ──────────────────────────────────────────────────────────────

/** sha256 helper returning a `Uint8Array`. */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/**
 * 32-byte PDA-seed input: identity bytes themselves when `length <= 32`,
 * `sha256(identity)` otherwise. Mirrors `IdentitySeed::default_from`.
 */
export function pdaSeedFromIdentity(identity: Uint8Array): Uint8Array {
  return identity.length <= 32 ? identity : sha256(identity);
}

/** Derive `(vector_pda, bump)`. Seeds: `["vector", identity_seed]`. */
export function findVectorPda(
  scheme: Scheme,
  identity: Uint8Array
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [VECTOR_PDA_SEED, pdaSeedFromIdentity(identity)],
    scheme.programId
  );
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
