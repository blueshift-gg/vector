/**
 * `Vector` — the scheme-agnostic core of the SDK.
 *
 * You authorize work in terms of plain Solana **instructions** (the CPIs to
 * run under the PDA); the SDK wires the `advance` + `passthrough` and the
 * transaction layout. Three ways to authorize, all returning ready-to-
 * broadcast {@link Artifact}s: {@link Vector.authorize} (one op),
 * {@link Vector.chain} (ordered, forward-secure), {@link Vector.branch}
 * (mutually-exclusive alternatives). {@link Vector.derive} gives independent
 * sub-accounts. Signing is synchronous and offline; only {@link Vector.nonce}
 * touches the network.
 *
 * Construct a `Vector` with a per-scheme constructor from its subpath so you
 * only pull the crypto you use, e.g.
 * `import { vectorEd25519 } from "vector-sdk/ed25519"`.
 */
import {
  Address,
  Connection,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";

import { Scheme, fetchVectorAccount } from "./scheme.js";
import {
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  createCloseSubinstruction,
} from "./instructions.js";
import {
  ChainSigner,
  signChain,
  signBranches,
  resolveChainStatus,
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
  /**
   * Verification public key when it differs from {@link identity} — i.e. the
   * Falcon/Hawk wire pubkey (`identity` is its `sha256`). Needed to verify the
   * artifact offline; omitted for schemes where `identity` is the key itself.
   */
  publicKey?: Uint8Array;
  /**
   * Index of the `advance` within {@link instructions}. 0 for most schemes;
   * non-zero when the scheme prepends instructions (e.g. Hawk-512's
   * compute-budget bump), which are committed to by the digest.
   */
  advanceIndex: number;
  /** Instructions to broadcast in order: `[...pre, advance, ...passthrough]`. */
  instructions: TransactionInstruction[];
  /** A fresh `Transaction` of {@link instructions} (relayer adds blockhash + fee-payer sig). */
  transaction(): Transaction;
}

/** The pieces a per-scheme constructor assembles into a {@link Vector}. */
export interface VectorParts {
  scheme: Scheme;
  signer: ChainSigner;
  pda: Address;
  /** Single-transaction registration instruction (single-tx schemes). */
  initIx?: (payer: Address) => TransactionInstruction;
  /** Multi-transaction registration groups (e.g. Hawk-512). */
  registerGroups?: (payer: Address) => TransactionInstruction[][];
  /** Derive an independent sub-account (omit for schemes without seed derivation). */
  deriveChild?: (index: number) => Vector;
  /** Verification pubkey when it differs from the identity (Falcon/Hawk wire). */
  publicKey?: Uint8Array;
  /** Top-level instructions prepended to every advance (e.g. compute budget). */
  preIxs?: TransactionInstruction[];
  feePayer?: Address;
}

export class Vector {
  /** The signing scheme (program) this account uses. */
  readonly scheme: Scheme;
  /** The client identity (Ed25519: the 32-byte public key). */
  readonly identity: Uint8Array;
  /** The account's PDA — its on-chain address. */
  readonly pda: Address;

  private readonly signer: ChainSigner;
  private readonly feePayer?: Address;
  private readonly initIx?: (payer: Address) => TransactionInstruction;
  private readonly registerGroups?: (payer: Address) => TransactionInstruction[][];
  private readonly deriveChild?: (index: number) => Vector;
  private readonly publicKey?: Uint8Array;
  private readonly preIxs: TransactionInstruction[];

  private constructor(args: VectorParts) {
    this.scheme = args.scheme;
    this.signer = args.signer;
    this.identity = args.signer.identity;
    this.pda = args.pda;
    this.initIx = args.initIx;
    this.registerGroups = args.registerGroups;
    this.feePayer = args.feePayer;
    this.deriveChild = args.deriveChild;
    this.publicKey = args.publicKey;
    this.preIxs = args.preIxs ?? [];
  }

  /**
   * Assemble a `Vector` from its parts. Used by the per-scheme constructors
   * (`vectorEd25519`, `vectorSecp256k1`, …) in the scheme subpath modules —
   * prefer those over calling this directly.
   */
  static fromParts(args: VectorParts): Vector {
    return new Vector(args);
  }

  /**
   * The one-time `initialize` instruction for single-transaction schemes.
   * Throws for schemes whose registration spans multiple transactions
   * (Hawk-512) — use {@link register} instead.
   */
  initialize(payer: Address): TransactionInstruction {
    if (!this.initIx) {
      throw new Error(
        `${this.scheme.programId.toBase58()} needs multi-transaction registration — use register()`
      );
    }
    return this.initIx(payer);
  }

  /**
   * All account-registration transactions, in order — one inner array per
   * transaction. Single-transaction schemes return one group of one
   * instruction; Hawk-512 returns three. Send each group as its own
   * transaction, in order.
   */
  register(payer: Address): TransactionInstruction[][] {
    if (this.registerGroups) return this.registerGroups(payer);
    if (this.initIx) return [[this.initIx(payer)]];
    throw new Error(`${this.scheme.programId.toBase58()} has no registration path`);
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
   * Authorize a SOL withdrawal from this account's PDA to `to`. Convenience
   * for the program's own `withdraw` instruction.
   */
  withdraw(nonce: Uint8Array, to: Address, lamports: bigint): Artifact {
    return this.authorize(
      nonce,
      createWithdrawSubinstruction(this.scheme, this.identity, to, lamports)
    );
  }

  /** Authorize closing this account, sending its remaining lamports to `to`. */
  close(nonce: Uint8Array, to: Address): Artifact {
    return this.authorize(
      nonce,
      createCloseSubinstruction(this.scheme, this.identity, to)
    );
  }

  /**
   * Authorize an ordered, forward-secure chain of ops starting at `nonce`.
   * Op `i` is signed against the nonce op `i-1` produces, so they can only
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
   * Returns an artifact per label. Each label is a single op; for multi-step
   * alternative chains drop to the low-level {@link signBranches}.
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
   * returned `Vector` has the same API and a distinct identity/PDA, and
   * inherits this account's `feePayer`. Unavailable for schemes without
   * seed-based derivation (Falcon/Hawk) — build those sub-accounts from their
   * own keypairs.
   */
  derive(index: number): Vector {
    if (!this.deriveChild) {
      throw new Error(
        `derive() is unavailable for ${this.scheme.programId.toBase58()} (no seed-based sub-key derivation); construct each sub-account from its own keypair`
      );
    }
    return this.deriveChild(index);
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
      advanceIx: a.instructions[a.advanceIndex],
      pre: a.instructions.slice(0, a.advanceIndex),
      post: a.instructions.slice(a.advanceIndex + 1),
    }));
    return resolveChainStatus(steps, currentNonce);
  }

  private toStep(op: Op): BranchStep {
    const ixs = Array.isArray(op) ? op : [op];
    const pre = this.preIxs.length ? this.preIxs : undefined;
    if (ixs.length === 0) return { pre };
    return {
      pre,
      post: [createPassthroughInstruction(this.scheme, this.identity, ixs)],
    };
  }

  private toArtifact(step: SignedStep): Artifact {
    const instructions = [...step.pre, step.advanceIx, ...step.post];
    return {
      programId: this.scheme.programId,
      identity: this.identity,
      nonce: step.nonce,
      nextNonce: step.nextNonce,
      feePayer: this.feePayer,
      publicKey: this.publicKey,
      advanceIndex: step.pre.length,
      instructions,
      transaction: () => new Transaction().add(...instructions),
    };
  }
}
