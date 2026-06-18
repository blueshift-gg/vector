/**
 * Branching: ergonomic helpers over Vector's forward-secure hashchain.
 *
 * Each nonce is `SHA256(pre || current_nonce || identity || post)`, so a
 * state binds to the exact transaction that produced it. From any state you
 * can pre-sign several alternative transactions ("branches"); whichever
 * lands first advances the chain onto its branch and atomically invalidates
 * the siblings (they were signed against a nonce that no longer exists). You
 * therefore "sign N full chains and execute one" — the design forces you to
 * be explicit about the exact sequence(s) of events that may occur.
 */
import { Address, Connection, TransactionInstruction } from "@solana/web3.js";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

import { Scheme, fetchVectorAccount } from "./scheme.js";
import {
  ED25519,
  ed25519Identity,
  signAdvanceInstructionEd25519,
} from "./schemes/ed25519.js";
import {
  SECP256K1,
  secp256k1Identity,
  signAdvanceInstructionSecp256k1,
} from "./schemes/secp256k1.js";
import {
  EIP191,
  eip191Identity,
  signAdvanceInstructionEip191,
} from "./schemes/eip191.js";
import {
  FALCON512,
  falcon512Identity,
  signAdvanceInstructionFalcon512,
  Falcon512Keypair,
} from "./schemes/falcon512.js";
import {
  HAWK512,
  hawk512Identity,
  signAdvanceInstructionHawk512,
  Hawk512Keypair,
} from "./schemes/hawk512.js";
import { advanceVectorDigest } from "./digest.js";

/** Per-scheme signer for a single chain (one key / identity). */
export interface ChainSigner {
  scheme: Scheme;
  identity: Uint8Array;
  /** Sign an advance over `(nonce, pre, post)` and return the advance ix. */
  sign(
    nonce: Uint8Array,
    pre: TransactionInstruction[],
    post: TransactionInstruction[],
    feePayer?: Address
  ): TransactionInstruction;
}

/** Ed25519 chain signer bound to a 32-byte private-key seed. */
export function ed25519ChainSigner(signingKey: Uint8Array): ChainSigner {
  return {
    scheme: ED25519,
    identity: ed25519Identity(signingKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionEd25519(signingKey, nonce, pre, post, feePayer),
  };
}

/** Plain secp256k1 ECDSA chain signer (32-byte private key). */
export function secp256k1ChainSigner(privateKey: Uint8Array): ChainSigner {
  return {
    scheme: SECP256K1,
    identity: secp256k1Identity(privateKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionSecp256k1(privateKey, nonce, pre, post, feePayer),
  };
}

/** EIP-191 (Ethereum) chain signer (32-byte secp256k1 private key). */
export function eip191ChainSigner(privateKey: Uint8Array): ChainSigner {
  return {
    scheme: EIP191,
    identity: eip191Identity(privateKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionEip191(privateKey, nonce, pre, post, feePayer),
  };
}

/** Falcon-512 (post-quantum) chain signer (1281-byte secret + 897-byte wire pubkey). */
export function falcon512ChainSigner(keypair: Falcon512Keypair): ChainSigner {
  return {
    scheme: FALCON512,
    identity: falcon512Identity(keypair.publicKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionFalcon512(keypair, nonce, pre, post, feePayer),
  };
}

/** Hawk-512 (post-quantum) chain signer (184-byte secret + 1024-byte wire pubkey). */
export function hawk512ChainSigner(keypair: Hawk512Keypair): ChainSigner {
  return {
    scheme: HAWK512,
    identity: hawk512Identity(keypair.publicKey),
    sign: (nonce, pre, post, feePayer) =>
      signAdvanceInstructionHawk512(keypair, nonce, pre, post, feePayer),
  };
}

/** One step in a chain: instructions placed around the advance. */
export interface BranchStep {
  /** Top-level ixs before the advance (committed to by the digest). */
  pre?: TransactionInstruction[];
  /** Top-level ixs after the advance, e.g. the passthrough. */
  post?: TransactionInstruction[];
}

/** A signed step: the advance, the exact ixs it commits to, and its nonces. */
export interface SignedStep {
  index: number;
  /** Nonce this step is signed against. */
  nonce: Uint8Array;
  /** Nonce the chain holds after this step executes. */
  nextNonce: Uint8Array;
  advanceIx: TransactionInstruction;
  pre: TransactionInstruction[];
  post: TransactionInstruction[];
}

/**
 * Pre-sign an ordered chain of steps starting at `startNonce`. Step i is
 * signed against the nonce produced by step i-1, so the steps can ONLY
 * execute in order (skipping or reordering changes the recomputed digest and
 * fails verification). Broadcast each step as a transaction laid out exactly
 * `[...pre, advanceIx, ...post]`.
 */
export function signChain(
  signer: ChainSigner,
  startNonce: Uint8Array,
  steps: BranchStep[],
  feePayer?: Address
): SignedStep[] {
  const out: SignedStep[] = [];
  let nonce = startNonce;
  steps.forEach((step, index) => {
    const pre = step.pre ?? [];
    const post = step.post ?? [];
    const advanceIx = signer.sign(nonce, pre, post, feePayer);
    const nextNonce = advanceVectorDigest(
      signer.scheme,
      nonce,
      signer.identity,
      pre,
      post,
      feePayer
    );
    out.push({ index, nonce, nextNonce, advanceIx, pre, post });
    nonce = nextNonce;
  });
  return out;
}

/** A labelled alternative: a full chain pre-signed from a shared parent. */
export interface Branch {
  label: string;
  /** Parent nonce all branches diverge from. */
  head: Uint8Array;
  steps: SignedStep[];
}

/**
 * Pre-sign several alternative chains from one `parentNonce`. All branch
 * heads are signed against the same parent, so executing any branch's first
 * step consumes the parent nonce and atomically orphans every sibling. This
 * is the "sign N full chains, execute one" primitive.
 */
export function signBranches(
  signer: ChainSigner,
  parentNonce: Uint8Array,
  branches: { label: string; steps: BranchStep[] }[],
  feePayer?: Address
): Branch[] {
  return branches.map((b) => ({
    label: b.label,
    head: parentNonce,
    steps: signChain(signer, parentNonce, b.steps, feePayer),
  }));
}

/** Where a pre-signed chain stands relative to the current on-chain nonce. */
export type ChainStatus =
  | { state: "pending"; nextStepIndex: number }
  | { state: "completed" }
  | { state: "orphaned" };

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Given a pre-signed chain and the current on-chain nonce, report whether
 * the chain is mid-flight (and which step is next), fully executed, or
 * orphaned (the nonce is on a sibling branch / unrelated state).
 */
export function resolveChainStatus(
  steps: SignedStep[],
  currentNonce: Uint8Array
): ChainStatus {
  for (let i = 0; i < steps.length; i++) {
    if (bytesEqual(steps[i].nonce, currentNonce)) {
      return { state: "pending", nextStepIndex: i };
    }
  }
  if (
    steps.length > 0 &&
    bytesEqual(steps[steps.length - 1].nextNonce, currentNonce)
  ) {
    return { state: "completed" };
  }
  return { state: "orphaned" };
}

/**
 * Which branch the chain has committed to, given the current on-chain nonce.
 * A branch is "won" once it is pending past its head or completed; returns
 * null while still at the shared parent (no branch chosen yet) or if the
 * nonce matches no branch.
 */
export function whichBranchWon(
  branches: Branch[],
  currentNonce: Uint8Array
): Branch | null {
  for (const b of branches) {
    const status = resolveChainStatus(b.steps, currentNonce);
    if (status.state === "completed") return b;
    if (status.state === "pending" && status.nextStepIndex > 0) return b;
  }
  return null;
}

/** Fetch the chain's on-chain nonce and resolve its status. */
export async function fetchChainStatus(
  connection: Connection,
  signer: ChainSigner,
  steps: SignedStep[]
): Promise<ChainStatus> {
  try {
    const account = await fetchVectorAccount(
      connection,
      signer.scheme,
      signer.identity
    );
    return resolveChainStatus(steps, account.nonce);
  } catch {
    return { state: "orphaned" };
  }
}

// ── Sub-key derivation (independent parallel chains) ──────────────────

/** Domain-separation salt for sub-account derivation; bumping it re-derives. */
export const LANE_KDF_SALT = new TextEncoder().encode("vector-lane-kdf-v1");

/**
 * Deterministic 32-byte child seed for an independent sub-account, derived
 * from a master seed via HKDF-SHA256 (domain-separated by scheme + index).
 * The same master always yields the same stable, independent sub-keys.
 */
export function deriveLaneSeed(
  masterSeed: Uint8Array,
  schemeName: string,
  index: number
): Uint8Array {
  if (!Number.isInteger(index) || index < 0) {
    throw new Error(`index must be a non-negative integer, got ${index}`);
  }
  const info = new TextEncoder().encode(`vector-lane:${schemeName}:${index}`);
  return hkdf(sha256, masterSeed, LANE_KDF_SALT, info, 32);
}
