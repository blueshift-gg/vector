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
import { ED25519, createInitializeEd25519 } from "./schemes/ed25519.js";
import { SECP256K1, createInitializeSecp256k1 } from "./schemes/secp256k1.js";
import { EIP191, createInitializeEip191 } from "./schemes/eip191.js";
import {
  FALCON512,
  createInitializeFalcon512,
  Falcon512Keypair,
} from "./schemes/falcon512.js";
import {
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  createCloseSubinstruction,
} from "./instructions.js";
import {
  ChainSigner,
  ed25519ChainSigner,
  secp256k1ChainSigner,
  eip191ChainSigner,
  falcon512ChainSigner,
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

  private readonly signer: ChainSigner;
  private readonly feePayer?: Address;
  private readonly initIx: (payer: Address) => TransactionInstruction;
  private readonly deriveChild?: (index: number) => Vector;

  private constructor(args: {
    scheme: Scheme;
    signer: ChainSigner;
    pda: Address;
    initIx: (payer: Address) => TransactionInstruction;
    feePayer?: Address;
    deriveChild?: (index: number) => Vector;
  }) {
    this.scheme = args.scheme;
    this.signer = args.signer;
    this.identity = args.signer.identity;
    this.pda = args.pda;
    this.initIx = args.initIx;
    this.feePayer = args.feePayer;
    this.deriveChild = args.deriveChild;
  }

  /** Bind a `Vector` to a 32-byte Ed25519 private-key seed. */
  static ed25519(key: Uint8Array, opts?: { feePayer?: Address }): Vector {
    const signer = ed25519ChainSigner(key);
    const [pda] = findVectorPda(ED25519, signer.identity);
    return new Vector({
      scheme: ED25519,
      signer,
      pda,
      initIx: (payer) => createInitializeEd25519(payer, signer.identity),
      feePayer: opts?.feePayer,
      deriveChild: (i) => Vector.ed25519(deriveLaneSeed(key, "ed25519", i), opts),
    });
  }

  /** Bind a `Vector` to a 32-byte plain secp256k1 (ECDSA) private key. */
  static secp256k1(privateKey: Uint8Array, opts?: { feePayer?: Address }): Vector {
    const signer = secp256k1ChainSigner(privateKey);
    const [pda] = findVectorPda(SECP256K1, signer.identity);
    return new Vector({
      scheme: SECP256K1,
      signer,
      pda,
      initIx: (payer) => createInitializeSecp256k1(payer, signer.identity),
      feePayer: opts?.feePayer,
      deriveChild: (i) =>
        Vector.secp256k1(deriveLaneSeed(privateKey, "secp256k1", i), opts),
    });
  }

  /** Bind a `Vector` to a 32-byte secp256k1 key, signing as an Ethereum (EIP-191) address. */
  static eip191(privateKey: Uint8Array, opts?: { feePayer?: Address }): Vector {
    const signer = eip191ChainSigner(privateKey);
    const [pda] = findVectorPda(EIP191, signer.identity);
    return new Vector({
      scheme: EIP191,
      signer,
      pda,
      initIx: (payer) => createInitializeEip191(payer, signer.identity),
      feePayer: opts?.feePayer,
      deriveChild: (i) =>
        Vector.eip191(deriveLaneSeed(privateKey, "eip191", i), opts),
    });
  }

  /**
   * Bind a `Vector` to a post-quantum Falcon-512 keypair. `derive` is
   * unavailable (Falcon has no 32-byte seed) — construct each sub-account from
   * its own keypair.
   */
  static falcon512(
    keypair: Falcon512Keypair,
    opts?: { feePayer?: Address }
  ): Vector {
    const signer = falcon512ChainSigner(keypair);
    const [pda] = findVectorPda(FALCON512, signer.identity);
    return new Vector({
      scheme: FALCON512,
      signer,
      pda,
      initIx: (payer) => createInitializeFalcon512(payer, keypair.publicKey),
      feePayer: opts?.feePayer,
    });
  }

  /** The one-time `initialize` instruction that creates this account on-chain. */
  initialize(payer: Address): TransactionInstruction {
    return this.initIx(payer);
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
   * for the program's own `withdraw` instruction — no need to reach for the
   * low-level builder or supply the scheme/identity.
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
   * inherits this account's `feePayer`.
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
   * `pending` (and which op is next), `completed`, or `orphaned`. Assumes
   * facade-shaped artifacts (`[advance, ...passthrough]`), which is everything
   * the facade emits.
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
