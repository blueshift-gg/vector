/**
 * Ed25519 integration tests. See `helpers.ts` for the shared scaffolding,
 * `vitest.config.ts` for the per-file parallelism setting.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  PublicKey,
  Connection,
  Keypair,
  SystemProgram,
} from "@solana/web3.js";
import {
  ED25519,
  findSystemPda,
  ed25519Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeEd25519,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createSystemPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionEd25519,
  advanceVectorDigest,
  NonceAccount,
  NONCE_ACCOUNT_LEN,
  VectorError,
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
  let vectorPda: PublicKey;
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
    const ix = createInitializeEd25519(feePayer.publicKey, ED25519_IDENTITY);
    const tx = [ix];
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      ED25519,
      ED25519_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);
    expect(account.systemBump).toBe(findSystemPda(vectorPda)[1]);

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
        signAdvanceInstructionEd25519(SIGNER_KEY, nonce, pre, post, feePayer.publicKey)
    );
  });

  test("withdraw lamports via advance", async () => {
    // A freshly-initialized account holds exactly its rent-exempt minimum,
    // and on-chain `withdraw` refuses to drop below that floor. Top the PDA
    // up first so there are withdrawable lamports above rent-exemption.
    const topUp = [
      SystemProgram.transfer({
        fromPubkey: feePayer.publicKey,
        toPubkey: vectorPda,
        lamports: 5_000_000,
      })
    ];
    await sendTx(connection, topUp, [feePayer]);

    const before = await connection.getAccountInfo(vectorPda);
    expect(before).not.toBeNull();
    const startingLamports = before!.lamports;
    const withdrawAmount = 1_000n;

    const withdrawSub = createWithdrawSubinstruction(
      ED25519,
      ED25519_IDENTITY,
      feePayer.publicKey,
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
      feePayer.publicKey
    );
    const tx = [advanceIx, passthroughIx];
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      ED25519,
      currentNonce,
      ED25519_IDENTITY,
      [],
      [passthroughIx],
      feePayer.publicKey
    );

    const after = await connection.getAccountInfo(vectorPda);
    expect(after).not.toBeNull();
    expect(Number(after!.lamports)).toBe(
      Number(startingLamports) - Number(withdrawAmount)
    );
  });

  test("system passthrough transfers from the system PDA", async () => {
    const [systemPda] = findSystemPda(vectorPda);
    await sendTx(
      connection,
      [
        SystemProgram.transfer({
          fromPubkey: feePayer.publicKey,
          toPubkey: systemPda,
          lamports: 5_000_000,
        })
      ],
      [feePayer]
    );
    const receiver = (await Keypair.generate()).publicKey;

    const pay = SystemProgram.transfer({
      fromPubkey: systemPda,
      toPubkey: receiver,
      lamports: 2_000_000,
    });
    const passthroughIx = createSystemPassthroughInstruction(
      ED25519,
      ED25519_IDENTITY,
      [pay]
    );
    const advanceIx = signAdvanceInstructionEd25519(
      SIGNER_KEY,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.publicKey
    );
    await sendTx(connection, [advanceIx, passthroughIx], [feePayer]);
    currentNonce = advanceVectorDigest(
      ED25519,
      currentNonce,
      ED25519_IDENTITY,
      [],
      [passthroughIx],
      feePayer.publicKey
    );

    expect(Number(await connection.getBalance(systemPda))).toBe(3_000_000);
    expect(Number(await connection.getBalance(receiver))).toBe(2_000_000);
  });

  test("a signature past its validUntil slot is refused", async () => {
    const slot = BigInt(await connection.getSlot());
    const passthroughIx = createPassthroughInstruction(ED25519, ED25519_IDENTITY, [
      createWithdrawSubinstruction(ED25519, ED25519_IDENTITY, feePayer.publicKey, 1n),
    ]);
    const advanceIx = signAdvanceInstructionEd25519(
      SIGNER_KEY,
      currentNonce,
      [],
      [passthroughIx],
      feePayer.publicKey,
      slot - 1n
    );
    await expect(
      sendTx(connection, [advanceIx, passthroughIx], [feePayer])
    ).rejects.toThrow(new RegExp(`custom program error: 0x${VectorError.Expired.toString(16)}`));
  });

  test("close vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      ED25519,
      ED25519_IDENTITY,
      feePayer.publicKey
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
      feePayer.publicKey
    );
    const tx = [advanceIx, passthroughIx];
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});
