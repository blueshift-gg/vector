/**
 * ML-DSA-44 (post-quantum) integration tests. Its 1,312-byte key and
 * 2,420-byte signature only fit a V1 transaction. See `helpers.ts`.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  PublicKey,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  MLDSA44,
  mldsa44Keygen,
  findVectorPda,
  fetchVectorAccount,
  createInitializeMlDsa44,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionMlDsa44,
  advanceVectorDigest,
  vectorAccountLen,
} from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendV1 } from "./helpers.js";

// Deterministic, so the PDA is stable against a fresh validator.
const KP = mldsa44Keygen(new Uint8Array(32).fill(0x44));
const IDENTITY = KP.publicKey;

describe("vector-mldsa44", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
    [vectorPda] = findVectorPda(MLDSA44, IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  // The account (21,932 bytes) takes three `initialize`s: the first creates
  // it with the key, the others grow it and prepare the key.
  test("initialize mldsa44 vector account", async () => {
    await sendV1(connection, createInitializeMlDsa44(feePayer.publicKey, KP.publicKey), [
      feePayer,
    ]);
    const info = await connection.getAccountInfo(vectorPda);
    expect(info!.data.length).toBe(vectorAccountLen(MLDSA44));
    currentNonce = new Uint8Array((await fetchVectorAccount(connection, MLDSA44, IDENTITY)).nonce);
  });

  test("advance with empty payload", async () => {
    const advance = signAdvanceInstructionMlDsa44(KP, currentNonce, [], [], feePayer.publicKey);
    await sendV1(connection, [advance], [feePayer]);
    currentNonce = advanceVectorDigest(MLDSA44, currentNonce, IDENTITY, [], [], feePayer.publicKey);
    const account = await fetchVectorAccount(connection, MLDSA44, IDENTITY);
    expect(account.nonce).toEqual(currentNonce);
  });

  test("a signature over another nonce is refused", async () => {
    const stale = signAdvanceInstructionMlDsa44(
      KP,
      new Uint8Array(32),
      [],
      [],
      feePayer.publicKey
    );
    await expect(sendV1(connection, [stale], [feePayer])).rejects.toThrow();
    const account = await fetchVectorAccount(connection, MLDSA44, IDENTITY);
    expect(account.nonce).toEqual(currentNonce);
  });

  test("withdraw lamports via advance", async () => {
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: feePayer.publicKey,
          toPubkey: vectorPda,
          lamports: 5_000_000,
        })
      ),
      [feePayer]
    );
    const before = (await connection.getAccountInfo(vectorPda))!.lamports;
    const passthrough = createPassthroughInstruction(MLDSA44, IDENTITY, [
      createWithdrawSubinstruction(MLDSA44, IDENTITY, feePayer.publicKey, 1_000n),
    ]);
    const advance = signAdvanceInstructionMlDsa44(
      KP,
      currentNonce,
      [],
      [passthrough],
      feePayer.publicKey
    );
    await sendV1(connection, [advance, passthrough], [feePayer]);
    currentNonce = advanceVectorDigest(
      MLDSA44,
      currentNonce,
      IDENTITY,
      [],
      [passthrough],
      feePayer.publicKey
    );
    const after = (await connection.getAccountInfo(vectorPda))!.lamports;
    expect(Number(after)).toBe(Number(before) - 1_000);
  });

  test("close mldsa44 vector account via advance", async () => {
    const passthrough = createPassthroughInstruction(MLDSA44, IDENTITY, [
      createCloseSubinstruction(MLDSA44, IDENTITY, feePayer.publicKey),
    ]);
    const advance = signAdvanceInstructionMlDsa44(
      KP,
      currentNonce,
      [],
      [passthrough],
      feePayer.publicKey
    );
    await sendV1(connection, [advance, passthrough], [feePayer]);
    expect(await connection.getAccountInfo(vectorPda)).toBeNull();
  });
});
