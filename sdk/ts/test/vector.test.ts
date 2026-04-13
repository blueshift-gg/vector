/**
 * Integration tests for the Vector TypeScript SDK.
 *
 * Prerequisites:
 *   1. Build the program:  cargo build-sbf --manifest-path programs/vector-program/Cargo.toml
 *   2. Start validator:    solana-test-validator --bpf-program vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV ./target/deploy/vector_program.so --mint EvFUfisEScFuZSqDXagC17m3bpP32B74dseMHtzQ5TNb --reset
 *   3. Run tests:          npm test
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
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
  findVectorPda,
  fetchVectorAccount,
  createInitializeInstruction,
  signAdvanceInstruction,
  signCloseInstruction,
  advanceVectorDigest,
} from "../src/index.js";

// ── Constants ────────────────────────────────────────────────────────

const RPC_URL = "http://localhost:8899";

const SIGNER_KEY = new Uint8Array(32);
SIGNER_KEY[31] = 0x01;

const SIGNER_ADDRESS = new PublicKey(
  "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt"
);

// Fixed fee payer — funded via --mint flag on solana-test-validator.
const FEE_PAYER_SEED = new Uint8Array(32);
FEE_PAYER_SEED[0] = 1;

// ── Helpers ──────────────────────────────────────────────────────────

function explorerLink(signature: string): string {
  return `https://explorer.solana.com/tx/${signature}?cluster=custom&customUrl=${RPC_URL}`;
}

async function sendTx(
  connection: Connection,
  tx: Transaction,
  signers: Keypair[]
): Promise<string> {
  const sig = await sendAndConfirmTransaction(connection, tx, signers);
  console.log(explorerLink(sig));
  return sig;
}

// ── Tests ────────────────────────────────────────────────────────────

describe("vector", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let vectorBump: number;
  let currentSeed: Uint8Array;

  // Token state (shared across advance tests)
  let mint: Keypair;
  let destination: PublicKey;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");
    feePayer = Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(SIGNER_ADDRESS);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  // ── Initialize ───────────────────────────────────────────────────

  test("initialize vector account", async () => {
    const ix = createInitializeInstruction(feePayer.publicKey, SIGNER_ADDRESS);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(connection, SIGNER_ADDRESS);
    expect(account.address.equals(SIGNER_ADDRESS)).toBe(true);
    expect(account.bump).toBe(vectorBump);

    // Seed is derived on-chain from address + slot hash.
    currentSeed = new Uint8Array(account.seed);
  });

  // ── Advance with SPL token round-trip ────────────────────────────

  test("advance: transfer mint authority, mint, transfer back", async () => {
    // 1. Create a mint with authority = vectorPda.
    mint = Keypair.generate();
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
    destination = getAssociatedTokenAddressSync(
      mint.publicKey,
      feePayer.publicKey
    );
    const createAtaTx = new Transaction().add(
      createAssociatedTokenAccountInstruction(
        feePayer.publicKey,
        destination,
        feePayer.publicKey,
        mint.publicKey
      )
    );
    await sendAndConfirmTransaction(connection, createAtaTx, [feePayer]);

    // 3. Build the three top-level instructions:
    //    [advance(CPI: set_authority PDA→EOA), mint_to, set_authority EOA→PDA]
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

    // 4. Sign the advance instruction.
    const advanceIx = signAdvanceInstruction(
      SIGNER_KEY,
      currentSeed,
      [pdaToEoa],
      [],
      [mintToIx, eoaToPda],
      feePayer.publicKey
    );

    // 5. Submit the transaction.
    const tx = new Transaction().add(advanceIx, mintToIx, eoaToPda);
    await sendTx(connection, tx, [feePayer]);

    // 6. Verify: seed advanced to the digest.
    const nextSeed = advanceVectorDigest(
      currentSeed,
      SIGNER_ADDRESS,
      [pdaToEoa],
      [],
      [mintToIx, eoaToPda],
      feePayer.publicKey
    );
    currentSeed = nextSeed;

    const account = await fetchVectorAccount(connection, SIGNER_ADDRESS);
    expect(Buffer.from(account.seed)).toEqual(Buffer.from(currentSeed));

    // Verify 10,000 tokens were minted.
    const tokenInfo = await getAccount(connection, destination);
    expect(tokenInfo.amount).toBe(BigInt(10_000));

    // Verify mint authority returned to PDA.
    const mintInfo = await getMint(connection, mint.publicKey);
    expect(mintInfo.mintAuthority!.equals(vectorPda)).toBe(true);
  });

  // ── Close ────────────────────────────────────────────────────────

  test("close vector account", async () => {
    const closeIx = signCloseInstruction(
      SIGNER_KEY,
      currentSeed,
      feePayer.publicKey,
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(closeIx);
    await sendTx(connection, tx, [feePayer]);

    // Vector PDA should be reclaimed by the runtime.
    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});
