/**
 * EIP-191 integration tests. See `helpers.ts` for shared scaffolding.
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
  EIP191,
  eip191Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeEip191,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionEip191,
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
const EIP191_IDENTITY = eip191Identity(SECP_KEY);

describe("vector-eip191", () => {
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

    [vectorPda, vectorBump] = findVectorPda(EIP191, EIP191_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize eip191 vector account", async () => {
    const ix = createInitializeEip191(feePayer.address, EIP191_IDENTITY);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      EIP191,
      EIP191_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionEip191(
      SECP_KEY,
      currentNonce,
      [],
      [],
      feePayer.address
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      EIP191,
      currentNonce,
      EIP191_IDENTITY,
      [],
      [],
      feePayer.address
    );

    const account = await fetchVectorAccount(
      connection,
      EIP191,
      EIP191_IDENTITY
    );
    expect(Buffer.from(account.nonce)).toEqual(Buffer.from(currentNonce));
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      EIP191,
      EIP191_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, pre, post) =>
        signAdvanceInstructionEip191(
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
      EIP191,
      EIP191_IDENTITY,
      feePayer.address,
      withdrawAmount
    );
    const passthroughIx = createPassthroughInstruction(
      EIP191,
      EIP191_IDENTITY,
      [withdrawSub]
    );
    const advanceIx = signAdvanceInstructionEip191(
      SECP_KEY,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      EIP191,
      currentNonce,
      EIP191_IDENTITY,
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

  test("close eip191 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      EIP191,
      EIP191_IDENTITY,
      feePayer.address
    );
    const passthroughIx = createPassthroughInstruction(
      EIP191,
      EIP191_IDENTITY,
      [closeSub]
    );
    const advanceIx = signAdvanceInstructionEip191(
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
