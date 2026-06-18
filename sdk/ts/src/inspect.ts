/**
 * Inspect, serialize, and offline-verify Vector {@link Artifact}s — so policy
 * engines and air-gapped reviewers see *intent* instead of an opaque blob, and
 * a counterparty can transport an artifact and check it without a chain.
 *
 * This module is **crypto-free**. Offline verification is dispatched through a
 * registry that each scheme subpath module populates on import — so
 * `verifyArtifact` only pulls the crypto for the schemes you actually import
 * (e.g. importing `vector-sdk/ed25519` registers Ed25519 verification).
 */
import { Address, Transaction, TransactionInstruction } from "@solana/web3.js";
import {
  Scheme,
  readU16LE,
  ADVANCE_DISCRIMINATOR,
  CLOSE_DISCRIMINATOR,
  WITHDRAW_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
} from "./scheme.js";
import { advanceVectorDigest } from "./digest.js";
import { Artifact } from "./vector.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

// ── Serialization ────────────────────────────────────────────────────

interface SerializedKey {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}
interface SerializedIx {
  programId: string;
  keys: SerializedKey[];
  data: string; // hex
}

function ixToSerialized(ix: TransactionInstruction): SerializedIx {
  return {
    programId: ix.programId.toBase58(),
    keys: ix.keys.map((k) => ({
      pubkey: k.pubkey.toBase58(),
      isSigner: k.isSigner,
      isWritable: k.isWritable,
    })),
    data: toHex(ix.data),
  };
}

function serializedToIx(s: SerializedIx): TransactionInstruction {
  return new TransactionInstruction({
    programId: new Address(s.programId),
    keys: s.keys.map((k) => ({
      pubkey: new Address(k.pubkey),
      isSigner: k.isSigner,
      isWritable: k.isWritable,
    })),
    data: Buffer.from(fromHex(s.data)),
  });
}

/** Deterministic JSON for transport. Equal artifacts → equal bytes. */
export function serializeArtifact(a: Artifact): string {
  return JSON.stringify({
    programId: a.programId.toBase58(),
    identity: toHex(a.identity),
    nonce: toHex(a.nonce),
    nextNonce: toHex(a.nextNonce),
    feePayer: a.feePayer ? a.feePayer.toBase58() : undefined,
    publicKey: a.publicKey ? toHex(a.publicKey) : undefined,
    advanceIndex: a.advanceIndex,
    instructions: a.instructions.map(ixToSerialized),
  });
}

/** Rebuild an {@link Artifact} from {@link serializeArtifact} output. */
export function deserializeArtifact(json: string): Artifact {
  const o = JSON.parse(json);
  const instructions = (o.instructions as SerializedIx[]).map(serializedToIx);
  return {
    programId: new Address(o.programId),
    identity: fromHex(o.identity),
    nonce: fromHex(o.nonce),
    nextNonce: fromHex(o.nextNonce),
    feePayer: o.feePayer ? new Address(o.feePayer) : undefined,
    publicKey: o.publicKey ? fromHex(o.publicKey) : undefined,
    advanceIndex: o.advanceIndex ?? 0,
    instructions,
    transaction: () => new Transaction().add(...instructions),
  };
}

// ── Decoding ─────────────────────────────────────────────────────────

/** A decoded sub-instruction from a passthrough payload. */
export interface DecodedIx {
  programId: Address;
  accounts: { pubkey: Address; isWritable: boolean }[];
  data: Uint8Array;
}

function decodePassthrough(passthrough: TransactionInstruction): DecodedIx[] {
  const data = new Uint8Array(passthrough.data);
  const numIxs = data[1];
  let dOff = 2;
  let kOff = 2; // keys: [vector_pda, instructions_sysvar, then per ix program+accounts]
  const out: DecodedIx[] = [];
  for (let i = 0; i < numIxs; i++) {
    const numAccounts = data[dOff];
    const dataLen = readU16LE(data, dOff + 1);
    const ixData = data.slice(dOff + 3, dOff + 3 + dataLen);
    dOff += 3 + dataLen;
    const programId = passthrough.keys[kOff].pubkey;
    const accounts = passthrough.keys
      .slice(kOff + 1, kOff + 1 + numAccounts)
      .map((k) => ({ pubkey: k.pubkey, isWritable: k.isWritable }));
    kOff += 1 + numAccounts;
    out.push({ programId, accounts, data: ixData });
  }
  return out;
}

/** Decode every CPI an artifact will execute under the PDA. */
export function decodeOps(a: Artifact): DecodedIx[] {
  const out: DecodedIx[] = [];
  for (const ix of a.instructions) {
    if (
      ix.programId.toBase58() === a.programId.toBase58() &&
      ix.data[0] === PASSTHROUGH_DISCRIMINATOR
    ) {
      out.push(...decodePassthrough(ix));
    }
  }
  return out;
}

// ── Intent summary ───────────────────────────────────────────────────

function readU64LE(b: Uint8Array, off: number): bigint {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(b[off + i]) << BigInt(8 * i);
  return v;
}
function short(a: Address): string {
  const s = a.toBase58();
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

/** Human-readable intent lines. Unknown programs render raw, never hidden. */
export function summarize(a: Artifact): string[] {
  const vector = a.programId.toBase58();
  return decodeOps(a).map((ix) => {
    const pid = ix.programId.toBase58();
    const raw = `unknown program ${short(ix.programId)}: ${ix.data.length} bytes, ${ix.accounts.length} accounts`;
    if (pid === vector && ix.data[0] === WITHDRAW_DISCRIMINATOR && ix.data.length >= 9 && ix.accounts.length >= 2) {
      return `Vector withdraw ${readU64LE(ix.data, 1)} lamports → ${short(ix.accounts[1].pubkey)}`;
    }
    if (pid === vector && ix.data[0] === CLOSE_DISCRIMINATOR && ix.accounts.length >= 2) {
      return `Vector close → ${short(ix.accounts[1].pubkey)}`;
    }
    if (pid === SYSTEM_PROGRAM && ix.data[0] === 2 && ix.data.length >= 12 && ix.accounts.length >= 2) {
      return `System transfer ${readU64LE(ix.data, 4)} lamports ${short(ix.accounts[0].pubkey)} → ${short(ix.accounts[1].pubkey)}`;
    }
    if (pid === TOKEN_PROGRAM && ix.data[0] === 3 && ix.data.length >= 9 && ix.accounts.length >= 2) {
      return `SPL transfer ${readU64LE(ix.data, 1)} ${short(ix.accounts[0].pubkey)} → ${short(ix.accounts[1].pubkey)}`;
    }
    return raw;
  });
}

/** A deterministic, human-readable review block for a policy engine / display. */
export function review(a: Artifact): string {
  const lines = ["VECTOR ARTIFACT"];
  lines.push(`scheme: ${a.programId.toBase58()}`);
  lines.push(`identity: ${toHex(a.identity).slice(0, 8)}…`);
  lines.push(`nonce: ${toHex(a.nonce).slice(0, 8)}…`);
  if (a.feePayer) lines.push(`fee payer: ${a.feePayer.toBase58()}`);
  lines.push("intent:");
  for (const line of summarize(a)) lines.push(`  - ${line}`);
  return lines.join("\n");
}

// ── Offline verification (registry) ──────────────────────────────────

/** Recompute-and-check verifier for one scheme's artifacts. */
export type ArtifactVerifier = (artifact: Artifact) => boolean;

const verifiers = new Map<string, ArtifactVerifier>();

/**
 * Register a scheme's offline verifier. Called at module load by each scheme
 * subpath (e.g. importing `vector-sdk/ed25519` registers Ed25519), so
 * {@link verifyArtifact} only pulls the crypto for imported schemes.
 */
export function registerArtifactVerifier(
  programId: Address,
  verify: ArtifactVerifier
): void {
  verifiers.set(programId.toBase58(), verify);
}

/**
 * Verify an artifact's signature offline. Throws if no verifier is registered
 * for its scheme — import the scheme module (e.g. `vector-sdk/ed25519`) to
 * register it.
 */
export function verifyArtifact(a: Artifact): boolean {
  const verify = verifiers.get(a.programId.toBase58());
  if (!verify) {
    throw new Error(
      `verifyArtifact: no verifier registered for ${a.programId.toBase58()} — import its scheme module (e.g. "vector-sdk/ed25519")`
    );
  }
  return verify(a);
}

/**
 * Shared helper for scheme verifiers: pull the advance signature and recompute
 * the canonical digest from a facade-shaped artifact (`[...pre, advance,
 * ...post]`). Returns `null` if the advance isn't an advance instruction.
 * Uses only native SHA-256 (via {@link advanceVectorDigest}) — no scheme
 * crypto — so this module stays free of the per-scheme libraries.
 */
export function artifactParts(
  a: Artifact,
  scheme: Scheme
): { signature: Uint8Array; digest: Uint8Array } | null {
  const advanceData = new Uint8Array(a.instructions[a.advanceIndex].data);
  if (advanceData[0] !== ADVANCE_DISCRIMINATOR) return null;
  const signature = advanceData.slice(1, 1 + scheme.signatureLen);
  const digest = advanceVectorDigest(
    scheme,
    a.nonce,
    a.identity,
    a.instructions.slice(0, a.advanceIndex),
    a.instructions.slice(a.advanceIndex + 1),
    a.feePayer
  );
  return { signature, digest };
}
