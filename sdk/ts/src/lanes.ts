/**
 * Lanes (secondary): independent parallel workstreams for one authority.
 * The PDA seeds are identity-only, so independent chains require independent
 * identities — derived deterministically as sub-keys (HKDF-SHA256) from a
 * master seed. Use this ONLY for non-exclusive parallelism (A-and-B); for
 * ordered or mutually-exclusive flows use `branching.ts`.
 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { Address } from "@solana/web3.js";

import { findVectorPda } from "./scheme.js";
import { ED25519, ed25519Identity } from "./schemes/ed25519.js";
import { ChainSigner, ed25519ChainSigner } from "./branching.js";

export const LANE_KDF_SALT = new TextEncoder().encode("vector-lane-kdf-v1");

export interface Lane {
  index: number;
  signingKey: Uint8Array;
  identity: Uint8Array;
  pda: Address;
  bump: number;
}

/** Deterministic 32-byte child seed for one lane (HKDF-SHA256). */
export function deriveLaneSeed(
  masterSeed: Uint8Array,
  schemeName: string,
  laneIndex: number
): Uint8Array {
  if (!Number.isInteger(laneIndex) || laneIndex < 0) {
    throw new Error(`laneIndex must be a non-negative integer, got ${laneIndex}`);
  }
  const info = new TextEncoder().encode(`vector-lane:${schemeName}:${laneIndex}`);
  return hkdf(sha256, masterSeed, LANE_KDF_SALT, info, 32);
}

/** Derive one Ed25519 lane (sub-key → identity → PDA). */
export function deriveEd25519Lane(masterSeed: Uint8Array, laneIndex: number): Lane {
  const signingKey = deriveLaneSeed(masterSeed, "ed25519", laneIndex);
  const identity = ed25519Identity(signingKey);
  const [pda, bump] = findVectorPda(ED25519, identity);
  return { index: laneIndex, signingKey, identity, pda, bump };
}

/** Derive `count` consecutive Ed25519 lanes from `start` (default 0). */
export function deriveEd25519LaneSet(
  masterSeed: Uint8Array,
  count: number,
  start = 0
): Lane[] {
  return Array.from({ length: count }, (_, i) =>
    deriveEd25519Lane(masterSeed, start + i)
  );
}

/** A `ChainSigner` for a lane — run any branching helper on it. */
export function laneChainSigner(lane: Lane): ChainSigner {
  return ed25519ChainSigner(lane.signingKey);
}
