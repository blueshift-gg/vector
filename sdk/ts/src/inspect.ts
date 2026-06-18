/**
 * Inspect, serialize, and offline-verify Vector {@link Artifact}s — so policy
 * engines and air-gapped reviewers see *intent* instead of signing an opaque
 * blob, and so a counterparty can transport an artifact and check it without a
 * chain connection.
 */
import { Address, Transaction, TransactionInstruction } from "@solana/web3.js";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { falcon512 as nobleFalcon } from "@noble/post-quantum/falcon.js";
import { hawk512 as nobleHawk } from "@blueshift-gg/hawk512";

import {
  Scheme,
  readU16LE,
  ADVANCE_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
  CLOSE_DISCRIMINATOR,
  WITHDRAW_DISCRIMINATOR,
} from "./scheme.js";
import { advanceVectorDigest } from "./digest.js";
import { ED25519 } from "./schemes/ed25519.js";
import { SECP256K1 } from "./schemes/secp256k1.js";
import { EIP191 } from "./schemes/eip191.js";
import { FALCON512 } from "./schemes/falcon512.js";
import { HAWK512 } from "./schemes/hawk512.js";
import { Artifact } from "./vector.js";

const toHex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const fromHex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/** Resolve a {@link Scheme} from its on-chain program id. */
export function schemeForProgramId(programId: Address | string): Scheme {
  const id = typeof programId === "string" ? programId : programId.toBase58();
  for (const s of [ED25519, SECP256K1, EIP191, FALCON512, HAWK512]) {
    if (s.programId.toBase58() === id) return s;
  }
  throw new Error(`unknown scheme program id: ${id}`);
}

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

// ── Offline verification ─────────────────────────────────────────────

const EIP191_PREFIX = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");

function eip191Hash(digest: Uint8Array): Uint8Array {
  const buf = new Uint8Array(EIP191_PREFIX.length + digest.length);
  buf.set(EIP191_PREFIX);
  buf.set(digest, EIP191_PREFIX.length);
  return keccak_256(buf);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * Recompute the canonical digest from the artifact's instruction layout and
 * verify the signature offline — no chain access. Supports the four facade
 * schemes (Ed25519, secp256k1, EIP-191, Falcon-512). Returns `false` for a
 * bad signature; **throws** for a scheme it can't verify offline (Hawk-512)
 * or a Falcon artifact missing its `publicKey`. Assumes facade-shaped
 * artifacts (`[advance, ...passthrough]`).
 */
export function verifyArtifact(a: Artifact): boolean {
  const scheme = schemeForProgramId(a.programId);
  const pid = scheme.programId.toBase58();

  const needsPubkey =
    pid === FALCON512.programId.toBase58() || pid === HAWK512.programId.toBase58();
  if (needsPubkey && !a.publicKey) {
    throw new Error(
      "verifyArtifact: post-quantum artifact is missing publicKey (the wire pubkey)"
    );
  }

  const idx = a.advanceIndex ?? 0;
  const advanceData = new Uint8Array(a.instructions[idx].data);
  if (advanceData[0] !== ADVANCE_DISCRIMINATOR) return false;
  const signature = advanceData.slice(1, 1 + scheme.signatureLen);
  const digest = advanceVectorDigest(
    scheme,
    a.nonce,
    a.identity,
    a.instructions.slice(0, idx),
    a.instructions.slice(idx + 1),
    a.feePayer
  );

  try {
    if (pid === ED25519.programId.toBase58()) {
      return ed25519.verify(signature, digest, a.identity);
    }
    if (pid === SECP256K1.programId.toBase58()) {
      return secp256k1.verify(signature, digest, a.identity);
    }
    if (pid === HAWK512.programId.toBase58()) {
      // Hawk signature is fixed-size — no length recovery needed (unlike Falcon).
      return nobleHawk.verify(signature, digest, a.publicKey!);
    }
    if (pid === EIP191.programId.toBase58()) {
      const recovered = secp256k1.Signature.fromCompact(signature.slice(0, 64))
        .addRecoveryBit(signature[64])
        .recoverPublicKey(eip191Hash(digest))
        .toRawBytes(false); // 65-byte uncompressed: 0x04 || x || y
      return bytesEqual(keccak_256(recovered.slice(1)).slice(12, 32), a.identity);
    }
    // Falcon-512: identity is sha256(wire), so verify against the wire pubkey.
    // The on-chain wire zero-pads the compressed signature to a fixed size,
    // but noble needs its exact detached length. Recover it by scanning from
    // the last non-zero byte up to the padded size — exactly one length
    // verifies (shorter truncates, longer carries trailing padding noble
    // rejects).
    let end = signature.length;
    while (end > 0 && signature[end - 1] === 0) end--;
    for (let len = end; len <= signature.length; len++) {
      try {
        if (nobleFalcon.verify(signature.slice(0, len), digest, a.publicKey!)) {
          return true;
        }
      } catch {
        // wrong length — keep scanning
      }
    }
    return false;
  } catch {
    return false;
  }
}

// ── Review rendering ─────────────────────────────────────────────────

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
