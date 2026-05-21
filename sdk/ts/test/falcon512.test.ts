/**
 * Falcon-512 (post-quantum) integration tests. See `helpers.ts` for shared
 * scaffolding.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  Address,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  FALCON512,
  falcon512Keygen,
  falcon512Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeFalcon512,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionFalcon512,
  advanceVectorDigest,
} from "../src/index.js";
import {
  RPC_URL,
  WS_URL,
  FEE_PAYER_SEED,
  sendTx,
  splMintAuthorityRoundTrip,
} from "./helpers.js";

// Falcon-512 deterministic test keypair (48-byte noble keygen seed) so the
// PDA is stable across the block and across runs against a fresh validator.
const FALCON_SEED = new Uint8Array(48);
FALCON_SEED[47] = 0x01;
const FALCON_KP = falcon512Keygen(FALCON_SEED);
const FALCON_IDENTITY = falcon512Identity(FALCON_KP.publicKey);

describe("vector-falcon512", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: Address;
  let vectorBump: number;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, {
      commitment: "confirmed",
      wsEndpoint: WS_URL,
    });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(FALCON512, FALCON_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  // Falcon-512 is single-step: its 1090-byte account fits one CPI
  // CreateAccount, so `initialize` registers it in a single call (the
  // wire pubkey is hashed + prepared on-chain at init).
  test("initialize falcon512 vector account", async () => {
    const ix = createInitializeFalcon512(feePayer.address, FALCON_KP.publicKey);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      FALCON512,
      FALCON_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  // Falcon advance verifies via the prepared pubkey (~184k CU, within the
  // 200k default per-instruction budget).
  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionFalcon512(
      FALCON_KP,
      currentNonce,
      [],
      [],
      feePayer.address
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      FALCON512,
      currentNonce,
      FALCON_IDENTITY,
      [],
      [],
      feePayer.address
    );

    const account = await fetchVectorAccount(
      connection,
      FALCON512,
      FALCON_IDENTITY
    );
    expect(account.nonce).toEqual(currentNonce);
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      FALCON512,
      FALCON_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, pre, post) =>
        signAdvanceInstructionFalcon512(
          FALCON_KP,
          nonce,
          pre,
          post,
          feePayer.address
        )
    );
  });

  test("withdraw lamports via advance", async () => {
    // A freshly-initialized account holds exactly its rent-exempt minimum,
    // and on-chain `withdraw` refuses to drop below that floor. Top the PDA
    // up first so there are withdrawable lamports above rent-exemption.
    const topUp = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: feePayer.address,
        toPubkey: vectorPda,
        lamports: 5_000_000,
      })
    );
    await sendAndConfirmTransaction(connection, topUp, [feePayer]);

    const before = await connection.getAccountInfo(vectorPda);
    expect(before).not.toBeNull();
    const startingLamports = before!.lamports;
    const withdrawAmount = 1_000n;

    const withdrawSub = createWithdrawSubinstruction(
      FALCON512,
      FALCON_IDENTITY,
      feePayer.address,
      withdrawAmount
    );
    const passthroughIx = createPassthroughInstruction(
      FALCON512,
      FALCON_IDENTITY,
      [withdrawSub]
    );
    const advanceIx = signAdvanceInstructionFalcon512(
      FALCON_KP,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      FALCON512,
      currentNonce,
      FALCON_IDENTITY,
      [],
      [passthroughIx],
      feePayer.address
    );

    const after = await connection.getAccountInfo(vectorPda);
    expect(after).not.toBeNull();
    expect(Number(after!.lamports)).toBe(
      Number(startingLamports) - Number(withdrawAmount)
    );
  });

  test("close falcon512 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      FALCON512,
      FALCON_IDENTITY,
      feePayer.address
    );
    const passthroughIx = createPassthroughInstruction(
      FALCON512,
      FALCON_IDENTITY,
      [closeSub]
    );
    const advanceIx = signAdvanceInstructionFalcon512(
      FALCON_KP,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});
