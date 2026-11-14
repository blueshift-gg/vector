/**
 * Shared scaffolding for the integration test files, one per scheme.
 *
 * Importing this module also applies the `PublicKey` shims that
 * `@solana/spl-token@0.4` (v1-API) expects and `@solana/web3.js@3` may not
 * provide: `toBuffer()` and a sync `findProgramAddressSync(...)`. They
 * install only if missing; subsequent imports are no-ops. Needs a validator:
 * `bun run validator`.
 */
import { expect } from "vitest";
import {
  PublicKey,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
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

// ── PublicKey shims (spl-token@0.4 expects v1 API) ─────────────────────

if (!(PublicKey.prototype as any).toBuffer) {
  (PublicKey.prototype as any).toBuffer = function () {
    return Buffer.from(this.toBytes());
  };
}
if (!(PublicKey as any).findProgramAddressSync) {
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
  (PublicKey as any).findProgramAddressSync = (
    seeds: Uint8Array[],
    programId: PublicKey
  ): [PublicKey, number] => {
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
        return [new PublicKey(hash), bump];
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
 * Send `instructions` as one V1 transaction (SIMD-0385): up to 4,096 bytes,
 * for ML-DSA-44's key and signature or several signers at once. A V1
 * transaction takes its limits from the message, not from Compute Budget
 * instructions, and has none without them.
 */
export async function sendV1(
  connection: Connection,
  instructions: TransactionInstruction[],
  signers: Keypair[],
  computeUnitLimit = 1_400_000
): Promise<string> {
  const { blockhash } = await connection.getLatestBlockhash();
  const message = new TransactionMessage({
    payerKey: signers[0].publicKey,
    instructions,
    recentBlockhash: blockhash,
  // A V1 transaction budgets zero for any limit it leaves out: loading the
  // program and accounts needs this one too. 64 MiB is the runtime's most.
  }).compileToV1Message({ computeUnitLimit, loadedAccountsDataSizeLimit: 64 * 1024 * 1024 });
  const tx = new VersionedTransaction(message);
  await tx.sign(signers);
  const sig = await connection.sendTransaction(tx);
  const { value } = await connection.confirmTransaction(sig, "confirmed");
  if (value.err) throw new Error(`${sig} failed: ${JSON.stringify(value.err)}`);
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
  vectorPda: PublicKey,
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
      fromPubkey: feePayer.publicKey,
      newAccountPubkey: mint.publicKey,
      space: MINT_SIZE,
      lamports: rentExempt,
      programId: TOKEN_PROGRAM_ID,
    }),
    createInitializeMint2Instruction(mint.publicKey, 6, vectorPda, null)
  );
  await sendAndConfirmTransaction(connection, createMintTx, [feePayer, mint]);

  // 2. Create an associated token account for the fee payer.
  const destination = getAssociatedTokenAddressSync(
    mint.publicKey,
    feePayer.publicKey
  );
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      createAssociatedTokenAccountInstruction(
        feePayer.publicKey,
        destination,
        feePayer.publicKey,
        mint.publicKey
      )
    ),
    [feePayer]
  );

  // 3. Tx layout: [advance, passthrough(set_authority PDA→EOA), mint_to,
  //    set_authority EOA→PDA]
  const pdaToEoa = createSetAuthorityInstruction(
    mint.publicKey,
    vectorPda,
    AuthorityType.MintTokens,
    feePayer.publicKey
  );
  const mintToIx = createMintToInstruction(
    mint.publicKey,
    destination,
    feePayer.publicKey,
    10_000
  );
  const eoaToPda = createSetAuthorityInstruction(
    mint.publicKey,
    feePayer.publicKey,
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
    feePayer.publicKey
  );

  const account = await fetchVectorAccount(connection, scheme, identity);
  expect(Buffer.from(account.nonce)).toEqual(Buffer.from(nextNonce));

  const tokenInfo = await getAccount(connection, destination);
  expect(tokenInfo.amount).toBe(BigInt(10_000));

  const mintInfo = await getMint(connection, mint.publicKey);
  // `getMint` returns `mintAuthority` as a v1-compat `PublicKey` whose
  // `.equals` reaches into `_bn`; the v3 `PublicKey` has no `_bn`, so compare
  // base58 strings instead.
  expect(mintInfo.mintAuthority!.toBase58()).toBe(vectorPda.toBase58());

  return nextNonce;
}
