/**
 * `Vector` — the front door to the Vector SDK.
 *
 * A `Vector` is bound once to a signing key and computes its on-chain
 * identity and PDA up front. You then authorize work in terms of plain
 * Solana **instructions** (the CPIs you want executed under the PDA); the
 * SDK wires the `advance` + `passthrough` and the transaction layout for you,
 * so you never assemble those by hand.
 *
 * Three ways to authorize, all returning ready-to-broadcast {@link Artifact}s:
 *
 * - {@link Vector.authorize} — one op.
 * - {@link Vector.chain} — an ordered, forward-secure sequence (each op can
 *   only execute after the previous one).
 * - {@link Vector.branch} — mutually-exclusive alternatives ("sign N, execute
 *   one"); whichever lands first orphans the rest.
 *
 * For independent, non-exclusive parallel work (e.g. many simultaneous RFQ
 * positions) derive sub-accounts with {@link Vector.derive} — each is another
 * `Vector` with the same API.
 *
 * Signing is **synchronous and offline** (air-gapped friendly): you pass the
 * nonce you signed against. The only networked call is {@link Vector.nonce},
 * which reads the current on-chain nonce.
 *
 * @example
 * ```ts
 * const v = Vector.ed25519(key, { feePayer });
 * const nonce = await v.nonce(connection);
 * const art = v.authorize(nonce, withdrawIx);   // op = Instruction | Instruction[]
 * await sendAndConfirmTransaction(connection, art.transaction(), [feePayer]);
 * ```
 */
import {
  Address,
  Connection,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import { Scheme, findVectorPda, fetchVectorAccount } from "./scheme.js";
import {
  ED25519,
  ed25519Identity,
  createInitializeEd25519,
} from "./schemes/ed25519.js";
import { createPassthroughInstruction } from "./instructions.js";
import {
  ChainSigner,
  ed25519ChainSigner,
  signChain,
  signBranches,
  resolveChainStatus,
  deriveLaneSeed,
  BranchStep,
  SignedStep,
  ChainStatus,
} from "./branching.js";

export type { ChainStatus } from "./branching.js";

/**
 * An op — the CPI(s) to run under the Vector PDA for one authorization.
 * A single instruction or a list; an empty list is an **inert advance**
 * (bumps the nonce with no side effects, i.e. a revocation).
 */
export type Op = TransactionInstruction | TransactionInstruction[];

/** A signed, broadcast-ready authorization with the advance/passthrough wired. */
export interface Artifact {
  /** The scheme program this artifact authorizes against. */
  programId: Address;
  /** The signing identity (Ed25519: the 32-byte public key). */
  identity: Uint8Array;
  /** Nonce this artifact is signed against; valid only while the PDA sits here. */
  nonce: Uint8Array;
  /** Nonce the chain holds after this artifact executes. */
  nextNonce: Uint8Array;
  /** Fee payer the digest was bound to, if any (needed to re-verify offline). */
  feePayer?: Address;
  /** Instructions to broadcast in order: `[advance]` or `[advance, passthrough]`. */
  instructions: TransactionInstruction[];
  /** A fresh `Transaction` of {@link instructions} (relayer adds blockhash + fee-payer sig). */
  transaction(): Transaction;
}

export class Vector {
  /** The signing scheme (program) this account uses. */
  readonly scheme: Scheme;
  /** The client identity (Ed25519: the 32-byte public key). */
  readonly identity: Uint8Array;
  /** The account's PDA — its on-chain address. */
  readonly pda: Address;

  private readonly key: Uint8Array;
  private readonly signer: ChainSigner;
  private readonly feePayer?: Address;

  private constructor(
    scheme: Scheme,
    key: Uint8Array,
    signer: ChainSigner,
    pda: Address,
    feePayer?: Address
  ) {
    this.scheme = scheme;
    this.key = key;
    this.signer = signer;
    this.identity = signer.identity;
    this.pda = pda;
    this.feePayer = feePayer;
  }

  /** Bind a `Vector` to a 32-byte Ed25519 private-key seed. */
  static ed25519(key: Uint8Array, opts?: { feePayer?: Address }): Vector {
    const signer = ed25519ChainSigner(key);
    const [pda] = findVectorPda(ED25519, signer.identity);
    return new Vector(ED25519, key, signer, pda, opts?.feePayer);
  }

  /** The one-time `initialize` instruction that creates this account on-chain. */
  initialize(payer: Address): TransactionInstruction {
    return createInitializeEd25519(payer, this.identity);
  }

  /** Read the current on-chain nonce. The only networked call. */
  async nonce(connection: Connection): Promise<Uint8Array> {
    const account = await fetchVectorAccount(connection, this.scheme, this.identity);
    return account.nonce;
  }

  /**
   * Authorize a single op at `nonce`. An empty op (`[]`) is an inert advance —
   * use it to **revoke** every artifact outstanding against `nonce`.
   */
  authorize(nonce: Uint8Array, op: Op): Artifact {
    return this.chain(nonce, [op])[0];
  }

  /**
   * Authorize an ordered, forward-secure chain of ops starting at `nonce`.
   * Op `i` is signed against the nonce op `i-1` produces, so the ops can only
   * execute in order. Broadcast each returned artifact's `transaction()`.
   */
  chain(nonce: Uint8Array, ops: Op[]): Artifact[] {
    const steps = signChain(
      this.signer,
      nonce,
      ops.map((op) => this.toStep(op)),
      this.feePayer
    );
    return steps.map((s) => this.toArtifact(s));
  }

  /**
   * Authorize mutually-exclusive alternatives from one `nonce`. All share the
   * same parent state, so executing any one orphans the rest atomically.
   * Returns an artifact per label.
   */
  branch(nonce: Uint8Array, named: Record<string, Op>): Record<string, Artifact> {
    const labels = Object.keys(named);
    const branches = signBranches(
      this.signer,
      nonce,
      labels.map((label) => ({ label, steps: [this.toStep(named[label])] })),
      this.feePayer
    );
    const out: Record<string, Artifact> = {};
    branches.forEach((b, i) => {
      out[labels[i]] = this.toArtifact(b.steps[0]);
    });
    return out;
  }

  /**
   * Derive an independent sub-account (its own chain) from this account's key.
   * Use for non-exclusive parallel work (e.g. one position per RFQ deal). The
   * returned `Vector` has the same API and a distinct identity/PDA.
   */
  derive(index: number): Vector {
    const childSeed = deriveLaneSeed(this.key, "ed25519", index);
    return Vector.ed25519(childSeed, { feePayer: this.feePayer });
  }

  /**
   * Where a pre-signed chain stands given the current on-chain nonce:
   * `pending` (and which op is next), `completed`, or `orphaned`.
   */
  status(artifacts: Artifact[], currentNonce: Uint8Array): ChainStatus {
    const steps: SignedStep[] = artifacts.map((a, index) => ({
      index,
      nonce: a.nonce,
      nextNonce: a.nextNonce,
      advanceIx: a.instructions[0],
      pre: [],
      post: a.instructions.slice(1),
    }));
    return resolveChainStatus(steps, currentNonce);
  }

  /** Wrap an op's CPIs in a passthrough (or nothing, for an inert advance). */
  private toStep(op: Op): BranchStep {
    const ixs = Array.isArray(op) ? op : [op];
    if (ixs.length === 0) return {};
    return { post: [createPassthroughInstruction(this.scheme, this.identity, ixs)] };
  }

  private toArtifact(step: SignedStep): Artifact {
    const instructions = [step.advanceIx, ...step.post];
    return {
      programId: this.scheme.programId,
      identity: this.identity,
      nonce: step.nonce,
      nextNonce: step.nextNonce,
      feePayer: this.feePayer,
      instructions,
      transaction: () => new Transaction().add(...instructions),
    };
  }
}
