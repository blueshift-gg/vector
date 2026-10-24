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
  closeNonceAccount,
  createNonceAccount,
  getNonce,
  NonceAccount,
  NoncedTransaction,
  systemAccount,
  NONCE_ACCOUNT_LEN,
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

  test("system passthrough transfers from the system PDA", async () => {
    const [systemPda] = findSystemPda(vectorPda);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(
        SystemProgram.transfer({
          fromPubkey: feePayer.address,
          toPubkey: systemPda,
          lamports: 5_000_000,
        })
      ),
      [feePayer]
    );
    const receiver = (await Keypair.generate()).address;

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
      feePayer.address
    );
    await sendTx(connection, new Transaction().add(advanceIx, passthroughIx), [feePayer]);
    currentNonce = advanceVectorDigest(
      ED25519,
      currentNonce,
      ED25519_IDENTITY,
      [],
      [passthroughIx],
      feePayer.address
    );

    expect(Number(await connection.getBalance(systemPda))).toBe(3_000_000);
    expect(Number(await connection.getBalance(receiver))).toBe(2_000_000);
  });

  test("durable nonce flow: sign offline, relay a plain Transaction", async () => {
    // A cold key with its vector, a nonce account and SOL at its system account.
    const authority = await Keypair.generate();
    const nonceKeypair = await Keypair.generate();
    const nonceAccount = nonceKeypair.address;
    const recipient = (await Keypair.generate()).address;
    const lamports = await connection.getMinimumBalanceForRentExemption(NONCE_ACCOUNT_LEN);
    const setup = createNonceAccount({
      fromPubkey: feePayer.address,
      noncePubkey: nonceAccount,
      authorizedPubkey: authority.address,
      lamports,
    });
    setup.instructions.unshift(
      createInitializeEd25519(feePayer.address, authority.address.toBytes()),
      SystemProgram.transfer({
        fromPubkey: feePayer.address,
        toPubkey: systemAccount(authority.address),
        lamports: 10_000_000,
      })
    );
    await sendTx(connection, setup, [feePayer, nonceKeypair]);
    // It signs from the slot after its creation.
    const { created } = NonceAccount.fromAccountData(
      (await connection.getAccountInfo(nonceAccount))!.data
    );
    while (BigInt(await connection.getSlot()) <= created) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Offline: the transfer names the authority, as under durable nonces.
    const signOver = async (amount: number) => {
      const nonce = await getNonce(connection, nonceAccount);
      const tx = new NoncedTransaction({
        feePayer: feePayer.address,
        nonceInfo: { nonce, nonceAccount, authority: authority.address },
      }).add(
        SystemProgram.transfer({ fromPubkey: authority.address, toPubkey: recipient, lamports: amount })
      );
      await tx.partialSign(authority);
      return tx;
    };
    const signed = await signOver(1_000_000);
    await expect(signed.partialSign(authority, feePayer)).rejects.toThrow("signs alone");
    const bytes = await signed.serialize({ requireAllSignatures: false });

    // The relayer: a plain Transaction, a recent blockhash, its own signature.
    const relay = async () => {
      const tx = Transaction.from(bytes);
      tx.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
      await tx.partialSign(feePayer);
      const signature = await connection.sendRawTransaction(await tx.serialize());
      return connection.confirmTransaction(signature, "confirmed");
    };
    expect((await relay()).value.err).toBeNull();
    expect(await connection.getBalance(recipient)).toBe(1_000_000n);
    // The same signed message never lands twice.
    await expect(relay()).rejects.toThrow(/missing required signature/);

    // Or in one process, with web3.js's own sender.
    await sendTx(connection, await signOver(2_000_000), [feePayer]);
    expect(await connection.getBalance(recipient)).toBe(3_000_000n);

    // Closing it returns the rent, as `nonceWithdraw` would.
    const close = new NoncedTransaction({
      feePayer: feePayer.address,
      nonceInfo: { nonce: await getNonce(connection, nonceAccount), nonceAccount, authority: authority.address },
    }).add(closeNonceAccount({ noncePubkey: nonceAccount, authorizedPubkey: authority.address, toPubkey: recipient }));
    await close.partialSign(authority);
    await sendTx(connection, close, [feePayer]);
    expect(await connection.getAccountInfo(nonceAccount)).toBeNull();
    expect(await connection.getBalance(recipient)).toBe(3_000_000n + BigInt(lamports));
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
