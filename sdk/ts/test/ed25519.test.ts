/**
 * Ed25519 integration tests. See `helpers.ts` for the shared scaffolding,
 * `vitest.config.ts` for the per-file parallelism setting.
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
  ED25519,
  ed25519Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeEd25519,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionEd25519,
  advanceVectorDigest,
} from "../src/index.js";
import {
  RPC_URL,
  WS_URL,
  FEE_PAYER_SEED,
  sendTx,
  splMintAuthorityRoundTrip,
} from "./helpers.js";

const SIGNER_KEY = new Uint8Array(32);
SIGNER_KEY[31] = 0x01;
const ED25519_IDENTITY = ed25519Identity(SIGNER_KEY);

describe("vector-ed25519", () => {
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

    [vectorPda, vectorBump] = findVectorPda(ED25519, ED25519_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize vector account", async () => {
    const ix = createInitializeEd25519(feePayer.address, ED25519_IDENTITY);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      ED25519,
      ED25519_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      ED25519,
      ED25519_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, pre, post) =>
        signAdvanceInstructionEd25519(SIGNER_KEY, nonce, pre, post, feePayer.address)
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
      ED25519,
      ED25519_IDENTITY,
      feePayer.address,
      withdrawAmount
    );
    const passthroughIx = createPassthroughInstruction(
      ED25519,
      ED25519_IDENTITY,
      [withdrawSub]
    );
    const advanceIx = signAdvanceInstructionEd25519(
      SIGNER_KEY,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      ED25519,
      currentNonce,
      ED25519_IDENTITY,
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

  test("close vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      ED25519,
      ED25519_IDENTITY,
      feePayer.address
    );
    const passthroughIx = createPassthroughInstruction(
      ED25519,
      ED25519_IDENTITY,
      [closeSub]
    );
    const advanceIx = signAdvanceInstructionEd25519(
      SIGNER_KEY,
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
