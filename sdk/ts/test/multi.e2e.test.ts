/**
 * Several signers in one `advance`, of different schemes: Ed25519 over a
 * nonce account of its vector, plain secp256k1 and EIP-191, then one
 * `passthrough` that withdraws from two of them. Checks the client verifier
 * against what the program accepts. Fits a legacy transaction. See
 * `helpers.ts`.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  PublicKey,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  ComputeBudgetProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  ED25519,
  FALCON512,
  SECP256K1,
  EIP191,
  NONCE_ACCOUNT_LEN,
  PROGRAM_ID,
  AdvanceSigner,
  advanceMessage,
  signerDigest,
  signedNonce,
  createInitializeEd25519,
  createInitializeSecp256k1,
  createInitializeEip191,
  createInitializeFalcon512,
  falcon512Keygen,
  signDigestFalcon512,
  createInitializeNonceInstruction,
  createMultiAdvanceInstruction,
  createMultiPassthroughInstruction,
  createWithdrawSubinstruction,
  ed25519Identity,
  secp256k1Identity,
  eip191Identity,
  signDigestEd25519,
  signDigestSecp256k1,
  signDigestEip191,
  fetchVectorAccount,
  fetchNonceAccount,
  findVectorPda,
  verifyAdvanceTransaction,
} from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendTx } from "./helpers.js";

// Keys of their own, so these accounts are not the other files'.
const ALICE_KEY = new Uint8Array(32).fill(0x61);
const BOB_KEY = new Uint8Array(32).fill(0x62);
const CAROL_KEY = new Uint8Array(32).fill(0x63);
const ALICE = ed25519Identity(ALICE_KEY);
const BOB = secp256k1Identity(BOB_KEY);
const CAROL = eip191Identity(CAROL_KEY);
const DAVE_KP = falcon512Keygen(new Uint8Array(48).fill(0x64));
const DAVE = DAVE_KP.publicKey;

describe("vector-multi", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let nonceAccount: Keypair;
  const [alicePda] = findVectorPda(ED25519, ALICE);
  const [bobPda] = findVectorPda(SECP256K1, BOB);
  const [carolPda] = findVectorPda(EIP191, CAROL);

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
    nonceAccount = await Keypair.fromSeed(new Uint8Array(32).fill(0x6e));
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize three vectors and a nonce account", async () => {
    await sendTx(
      connection,
      new Transaction().add(
        createInitializeEd25519(feePayer.publicKey, ALICE),
        createInitializeSecp256k1(feePayer.publicKey, BOB),
        createInitializeEip191(feePayer.publicKey, CAROL),
        ...[alicePda, bobPda].map((toPubkey) =>
          SystemProgram.transfer({ fromPubkey: feePayer.publicKey, toPubkey, lamports: 5_000_000 })
        )
      ),
      [feePayer]
    );

    const rent = await connection.getMinimumBalanceForRentExemption(NONCE_ACCOUNT_LEN);
    await sendTx(
      connection,
      new Transaction().add(
        SystemProgram.createAccount({
          fromPubkey: feePayer.publicKey,
          newAccountPubkey: nonceAccount.publicKey,
          space: NONCE_ACCOUNT_LEN,
          lamports: rent,
          programId: PROGRAM_ID,
        }),
        createInitializeNonceInstruction(nonceAccount.publicKey, alicePda)
      ),
      [feePayer, nonceAccount]
    );
    const nonce = await fetchNonceAccount(connection, nonceAccount.publicKey);
    expect(nonce.vector.toBase58()).toBe(alicePda.toBase58());

    // A nonce account signs from the slot after the one it was created in.
    while (BigInt(await connection.getSlot("confirmed")) <= nonce.created) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  });

  test("three schemes sign one advance; one passthrough spends two vectors", async () => {
    const [alice, bob, carol] = await Promise.all([
      fetchVectorAccount(connection, ED25519, ALICE),
      fetchVectorAccount(connection, SECP256K1, BOB),
      fetchVectorAccount(connection, EIP191, CAROL),
    ]);
    const nonce = await fetchNonceAccount(connection, nonceAccount.publicKey);

    const passthrough = createMultiPassthroughInstruction(
      [
        { scheme: ED25519, identity: ALICE },
        { scheme: SECP256K1, identity: BOB },
      ],
      [
        createWithdrawSubinstruction(ED25519, ALICE, feePayer.publicKey, 1_000n),
        createWithdrawSubinstruction(SECP256K1, BOB, feePayer.publicKey, 2_000n),
      ]
    );
    const signers: AdvanceSigner[] = [
      { scheme: ED25519, identity: ALICE, nonceAccount: nonceAccount.publicKey },
      { scheme: SECP256K1, identity: BOB },
      { scheme: EIP191, identity: CAROL },
    ];
    const message = advanceMessage(signers, [], [passthrough], feePayer.publicKey);
    const aliceDigest = signerDigest(message, signedNonce(nonce.nonce, alice.nonce), alicePda);
    const bobDigest = signerDigest(message, bob.nonce, bobPda);
    const carolDigest = signerDigest(message, carol.nonce, carolPda);
    const advance = createMultiAdvanceInstruction([
      { ...signers[0], signature: signDigestEd25519(ALICE_KEY, aliceDigest) },
      { ...signers[1], signature: signDigestSecp256k1(BOB_KEY, bobDigest) },
      { ...signers[2], signature: signDigestEip191(CAROL_KEY, carolDigest) },
    ]);

    // The client verifier agrees with the program before anything is sent.
    const vectors = [
      { scheme: ED25519, identity: ALICE, nonce: alice.nonce },
      { scheme: SECP256K1, identity: BOB, nonce: bob.nonce },
      { scheme: EIP191, identity: CAROL, nonce: carol.nonce },
    ];
    const nonceAccounts = [
      { address: nonceAccount.publicKey, nonce: nonce.nonce, vector: alicePda },
    ];
    const transaction: TransactionInstruction[] = [advance, passthrough];
    const verified = verifyAdvanceTransaction({
      transaction,
      vectors,
      nonceAccounts,
      feePayer: feePayer.publicKey,
    });
    expect(verified.ok).toBe(true);
    expect(verified.signers.map((s) => Buffer.from(s.digest).toString("hex"))).toEqual(
      [aliceDigest, bobDigest, carolDigest].map((d) => Buffer.from(d).toString("hex"))
    );

    const balance = async (address: PublicKey) =>
      Number((await connection.getAccountInfo(address))!.lamports);
    const [aliceBefore, bobBefore] = [await balance(alicePda), await balance(bobPda)];
    await sendTx(connection, new Transaction().add(...transaction), [feePayer]);

    // Alice's signature moved her nonce account, not her vector.
    expect((await fetchNonceAccount(connection, nonceAccount.publicKey)).nonce).toEqual(
      aliceDigest
    );
    expect((await fetchVectorAccount(connection, ED25519, ALICE)).nonce).toEqual(alice.nonce);
    expect((await fetchVectorAccount(connection, SECP256K1, BOB)).nonce).toEqual(bobDigest);
    expect((await fetchVectorAccount(connection, EIP191, CAROL)).nonce).toEqual(carolDigest);
    expect(await balance(alicePda)).toBe(aliceBefore - 1_000);
    expect(await balance(bobPda)).toBe(bobBefore - 2_000);

    // Sent again, every signature is over a nonce that moved.
    await expect(
      sendAndConfirmTransaction(connection, new Transaction().add(...transaction), [feePayer])
    ).rejects.toThrow();
    const stale = verifyAdvanceTransaction({
      transaction,
      vectors: [
        { ...vectors[0], nonce: alice.nonce },
        { ...vectors[1], nonce: bobDigest },
        { ...vectors[2], nonce: carolDigest },
      ],
      nonceAccounts: [{ ...nonceAccounts[0], nonce: aliceDigest }],
      feePayer: feePayer.publicKey,
    });
    expect(stale.signers.map((s) => s.ok)).toEqual([false, false, false]);
  });

  // Falcon-512 verifies in about 170K CU and plain secp256k1 is plain-Rust
  // curve math, so with both the `advance` can pass the 200K a legacy
  // transaction gives an instruction by default. A `SetComputeUnitLimit`
  // before it raises that, and the message covers it like any instruction.
  test("Falcon-512 with other signers and the compute budget", async () => {
    await sendTx(
      connection,
      new Transaction().add(createInitializeFalcon512(feePayer.publicKey, DAVE)),
      [feePayer]
    );
    const [davePda] = findVectorPda(FALCON512, DAVE);
    const sign = async (pre: TransactionInstruction[]) => {
      const [alice, bob, dave] = await Promise.all([
        fetchVectorAccount(connection, ED25519, ALICE),
        fetchVectorAccount(connection, SECP256K1, BOB),
        fetchVectorAccount(connection, FALCON512, DAVE),
      ]);
      const signers: AdvanceSigner[] = [
        { scheme: ED25519, identity: ALICE },
        { scheme: SECP256K1, identity: BOB },
        { scheme: FALCON512, identity: DAVE },
      ];
      const message = advanceMessage(signers, pre, [], feePayer.publicKey);
      const digests = [
        signerDigest(message, alice.nonce, alicePda),
        signerDigest(message, bob.nonce, bobPda),
        signerDigest(message, dave.nonce, davePda),
      ];
      const advance = createMultiAdvanceInstruction([
        { ...signers[0], signature: signDigestEd25519(ALICE_KEY, digests[0]) },
        { ...signers[1], signature: signDigestSecp256k1(BOB_KEY, digests[1]) },
        { ...signers[2], signature: signDigestFalcon512(DAVE_KP, digests[2]) },
      ]);
      return { transaction: new Transaction().add(...pre, advance), daveDigest: digests[2] };
    };

    const budgeted = await sign([ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 })]);
    const signature = await sendTx(connection, budgeted.transaction, [feePayer]);
    expect((await fetchVectorAccount(connection, FALCON512, DAVE)).nonce).toEqual(
      budgeted.daveDigest
    );
    const landed = await connection.getTransaction(signature, {
      commitment: "confirmed",
      maxSupportedTransactionVersion: 1,
    });
    const units = Number(landed!.meta!.computeUnitsConsumed);
    console.log(`Ed25519 + secp256k1 + Falcon-512 advance: ${units} CU`);

    // Without the budget, the same signers fail exactly when they need more
    // than the default, and nothing moves.
    const unbudgeted = await sign([]);
    const sent = sendAndConfirmTransaction(connection, unbudgeted.transaction, [feePayer]);
    if (units > 200_000) {
      await expect(sent).rejects.toThrow();
      expect((await fetchVectorAccount(connection, FALCON512, DAVE)).nonce).toEqual(
        budgeted.daveDigest
      );
    } else {
      await sent;
    }
  });
});
