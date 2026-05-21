/**
 * Shared scaffolding for the per-scheme integration test files.
 *
 * Importing this module also applies the `Address` shims that
 * `@solana/spl-token@0.4` (v1-API) expects but `@solana/web3.js@3` no longer
 * provides: `toBuffer()` and a sync `findProgramAddressSync(...)`. The shims
 * install on first import; subsequent imports are no-ops.
 */
import { expect } from "vitest";
import {
  Address,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  AuthorityType,
  createAssociatedTokenAccountInstruction,
  createMintToInstruction,
  createSetAuthorityInstruction,
  getAccount,
  getAssociatedTokenAddressSync,
  getMint,
  createInitializeMint2Instruction,
  MINT_SIZE,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

import {
  Scheme,
  advanceVectorDigest,
  fetchVectorAccount,
  createPassthroughInstruction,
} from "../src/index.js";

// ── Address shims (spl-token@0.4 expects v1 API) ─────────────────────

if (!(Address.prototype as any).toBuffer) {
  (Address.prototype as any).toBuffer = function () {
    return Buffer.from(this.toBytes());
  };
}
if (!(Address as any).findProgramAddressSync) {
  const { createHash } = await import("crypto");
  const { ed25519 } = await import("@noble/curves/ed25519.js");
  const PDA_MARKER = new TextEncoder().encode("ProgramDerivedAddress");
  const sha256 = (data: Uint8Array): Uint8Array =>
    new Uint8Array(createHash("sha256").update(data).digest());
  const isOnCurve = (p: Uint8Array): boolean => {
    try {
      (ed25519 as any).Point.fromBytes(p);
      return true;
    } catch {
      return false;
    }
  };
  (Address as any).findProgramAddressSync = (
    seeds: Uint8Array[],
    programId: Address
  ): [Address, number] => {
    const programBytes = programId.toBytes();
    const totalLen =
      seeds.reduce((n, s) => n + s.length, 0) + 1 + programBytes.length + PDA_MARKER.length;
    const buf = new Uint8Array(totalLen);
    let off = 0;
    for (const s of seeds) {
      buf.set(s, off);
      off += s.length;
    }
    const bumpOff = off++;
    buf.set(programBytes, off);
    off += programBytes.length;
    buf.set(PDA_MARKER, off);
    for (let bump = 255; bump >= 0; bump--) {
      buf[bumpOff] = bump;
      const hash = sha256(buf);
      if (!isOnCurve(hash)) {
        return [new Address(hash), bump];
      }
    }
    throw new Error("Unable to find a viable PDA bump seed");
  };
}

// ── Constants ────────────────────────────────────────────────────────

export const RPC_URL = "http://localhost:8899";
export const WS_URL = "ws://localhost:8900";

/** Fixed fee payer — funded via `--mint` on `solana-test-validator`. */
export const FEE_PAYER_SEED = new Uint8Array(32);
FEE_PAYER_SEED[0] = 1;

// ── Helpers ──────────────────────────────────────────────────────────

export function explorerLink(signature: string): string {
  return `https://explorer.solana.com/tx/${signature}?cluster=custom&customUrl=${RPC_URL}`;
}

export async function sendTx(
  connection: Connection,
  tx: Transaction,
  signers: Keypair[]
): Promise<string> {
  const sig = await sendAndConfirmTransaction(connection, tx, signers);
  console.log(explorerLink(sig));
  return sig;
}

/**
 * SPL mint-authority round-trip: temporarily hands a mint's authority from
 * the vector PDA to an EOA, mints, and hands it back — all authorised by a
 * single signed `advance` whose digest commits to a sibling `passthrough`
 * (running the PDA→EOA `set_authority` CPI) plus the `mint_to` + EOA→PDA
 * `set_authority` post-instructions. Mirrors the Rust `run_round_trip_spl`.
 * Returns the advanced nonce.
 *
 * `signAdvance` is the scheme's signer closure already bound to its key and
 * the fee payer: `(nonce, pre, post) => advanceInstruction`. The
 * passthrough is built here and threaded through `post`, so the closure
 * stays signer-only.
 */
export async function splMintAuthorityRoundTrip(
  connection: Connection,
  feePayer: Keypair,
  scheme: Scheme,
  identity: Uint8Array,
  vectorPda: Address,
  currentNonce: Uint8Array,
  signAdvance: (
    nonce: Uint8Array,
    pre: TransactionInstruction[],
    post: TransactionInstruction[]
  ) => TransactionInstruction,
  // Top-level instructions placed BEFORE `advance` (e.g. a `ComputeBudget`
  // bump for heavy schemes). Committed to by the digest, so threaded
  // through both the signer closure and the nextNonce recompute.
  extraPreInstructions: TransactionInstruction[] = []
): Promise<Uint8Array> {
  // 1. Create a mint with authority = vectorPda.
  const mint = await Keypair.generate();
  const rentExempt = await connection.getMinimumBalanceForRentExemption(
    MINT_SIZE
  );
  const createMintTx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: feePayer.address,
      newAccountPubkey: mint.address,
      space: MINT_SIZE,
      lamports: rentExempt,
      programId: TOKEN_PROGRAM_ID,
    }),
    createInitializeMint2Instruction(mint.address, 6, vectorPda, null)
  );
  await sendAndConfirmTransaction(connection, createMintTx, [feePayer, mint]);

  // 2. Create an associated token account for the fee payer.
  const destination = getAssociatedTokenAddressSync(
    mint.address,
    feePayer.address
  );
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      createAssociatedTokenAccountInstruction(
        feePayer.address,
        destination,
        feePayer.address,
        mint.address
      )
    ),
    [feePayer]
  );

  // 3. Tx layout: [advance, passthrough(set_authority PDA→EOA), mint_to,
  //    set_authority EOA→PDA]
  const pdaToEoa = createSetAuthorityInstruction(
    mint.address,
    vectorPda,
    AuthorityType.MintTokens,
    feePayer.address
  );
  const mintToIx = createMintToInstruction(
    mint.address,
    destination,
    feePayer.address,
    10_000
  );
  const eoaToPda = createSetAuthorityInstruction(
    mint.address,
    feePayer.address,
    AuthorityType.MintTokens,
    vectorPda
  );

  // 4. Sign + submit. The PDA→EOA CPI lives in a `passthrough` ix that
  //    follows `advance`; advance's digest commits to the passthrough's
  //    bytes (plus mint_to + EOA→PDA) via post-instructions. Any
  //    `extraPreInstructions` are committed to as pre-instructions and
  //    must appear before `advance` in the actual transaction in the
  //    same order.
  const passthroughIx = createPassthroughInstruction(scheme, identity, [pdaToEoa]);
  const postIxs = [passthroughIx, mintToIx, eoaToPda];
  const advanceIx = signAdvance(currentNonce, extraPreInstructions, postIxs);
  await sendTx(
    connection,
    new Transaction().add(...extraPreInstructions, advanceIx, ...postIxs),
    [feePayer]
  );

  // 5. Verify: nonce advanced to the digest, tokens minted, authority back.
  const nextNonce = advanceVectorDigest(
    scheme,
    currentNonce,
    identity,
    extraPreInstructions,
    postIxs,
    feePayer.address
  );

  const account = await fetchVectorAccount(connection, scheme, identity);
  expect(Buffer.from(account.nonce)).toEqual(Buffer.from(nextNonce));

  const tokenInfo = await getAccount(connection, destination);
  expect(tokenInfo.amount).toBe(BigInt(10_000));

  const mintInfo = await getMint(connection, mint.address);
  // `getMint` returns `mintAuthority` as a v1-compat `PublicKey` whose
  // `.equals` reaches into `_bn`; the v3 `Address` has no `_bn`, so compare
  // base58 strings instead.
  expect(mintInfo.mintAuthority!.toBase58()).toBe(vectorPda.toBase58());

  return nextNonce;
}
