/**
 * secp256k1 (plain ECDSA) integration tests. See `helpers.ts` for shared
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
  SECP256K1,
  secp256k1Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeSecp256k1,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionSecp256k1,
  advanceVectorDigest,
} from "../src/index.js";
import {
  RPC_URL,
  WS_URL,
  FEE_PAYER_SEED,
  sendTx,
  splMintAuthorityRoundTrip,
} from "./helpers.js";

const SECP_KEY = new Uint8Array(32);
SECP_KEY[31] = 0x01;
const SECP256K1_IDENTITY = secp256k1Identity(SECP_KEY);

describe("vector-secp256k1", () => {
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

    [vectorPda, vectorBump] = findVectorPda(SECP256K1, SECP256K1_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize secp256k1 vector account", async () => {
    const ix = createInitializeSecp256k1(feePayer.address, SECP256K1_IDENTITY);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      SECP256K1,
      SECP256K1_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionSecp256k1(
      SECP_KEY,
      currentNonce,
      [],
      [],
      feePayer.address
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      SECP256K1,
      currentNonce,
      SECP256K1_IDENTITY,
      [],
      [],
      feePayer.address
    );

    const account = await fetchVectorAccount(
      connection,
      SECP256K1,
      SECP256K1_IDENTITY
    );
    expect(account.nonce).toEqual(currentNonce);
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      SECP256K1,
      SECP256K1_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, pre, post) =>
        signAdvanceInstructionSecp256k1(
          SECP_KEY,
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
      SECP256K1,
      SECP256K1_IDENTITY,
      feePayer.address,
      withdrawAmount
    );
    const passthroughIx = createPassthroughInstruction(
      SECP256K1,
      SECP256K1_IDENTITY,
      [withdrawSub]
    );
    const advanceIx = signAdvanceInstructionSecp256k1(
      SECP_KEY,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      SECP256K1,
      currentNonce,
      SECP256K1_IDENTITY,
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

  test("close secp256k1 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      SECP256K1,
      SECP256K1_IDENTITY,
      feePayer.address
    );
    const passthroughIx = createPassthroughInstruction(
      SECP256K1,
      SECP256K1_IDENTITY,
      [closeSub]
    );
    const advanceIx = signAdvanceInstructionSecp256k1(
      SECP_KEY,
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
