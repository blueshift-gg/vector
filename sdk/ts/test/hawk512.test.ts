/**
 * Hawk-512 (post-quantum) integration tests. See `helpers.ts` for shared
 * scaffolding.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  Address,
  ComputeBudgetProgram,
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  HAWK512,
  hawk512Keygen,
  hawk512Identity,
  findVectorPda,
  fetchVectorAccount,
  createInitializeHawk512,
  createHawk512StoreWire,
  createHawk512Finalize,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  signAdvanceInstructionHawk512,
  advanceVectorDigest,
} from "../src/index.js";
import {
  RPC_URL,
  WS_URL,
  FEE_PAYER_SEED,
  sendTx,
  splMintAuthorityRoundTrip,
} from "./helpers.js";

// Hawk-512 deterministic test keypair (SHAKE256(seed) continuous stream;
// the seed is also the cross-language KAT oracle used by the Rust signer).
const HAWK_SEED = new Uint8Array(48);
HAWK_SEED[47] = 0x01;
const HAWK_KP = hawk512Keygen(HAWK_SEED);
const HAWK_IDENTITY = hawk512Identity(HAWK_KP.publicKey);

describe("vector-hawk512", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: Address;
  let vectorBump: number;
  let currentNonce: Uint8Array;
  // Hawk advance is ~365 k CU (above the 200 k default per-ix budget).
  // Threaded as a top-level pre-instruction so it's committed to by the
  // digest. `finalize` uses a standalone CU bump — see step 3 below.
  let cuIx: TransactionInstruction;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, {
      commitment: "confirmed",
      wsEndpoint: WS_URL,
    });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(HAWK512, HAWK_IDENTITY);
    cuIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  // Hawk's 18.5 KB account can't be created in one CPI and its 1024-byte
  // wire pubkey can't coexist with the `system_program` meta required by
  // `CreateAccount`, so registration is three permissionless ixs, each
  // in its own tx:
  // 1. `initialize` commits `sha256(wire)` + allocates the ~10 KB base.
  // 2. `store_wire` ships the wire, verifies `sha256 == commit`, stashes it.
  // 3. `finalize` resizes to ~18.5 KB and runs `prepare_into` (paired with
  //    a `setComputeUnitLimit(600_000)` ix to cover `prepare_into`'s ~410 k
  //    draw on the live validator).
  test("step 1 — initialize commits sha256(wire), allocates base", async () => {
    // 32-byte payload + 3 metas fits ~270 bytes — plain legacy tx, no ALT.
    const ix = createInitializeHawk512(feePayer.address, HAWK_KP.publicKey);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(ix),
      [feePayer]
    );

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).not.toBeNull();
    expect(info!.owner.equals(HAWK512.programId)).toBe(true);
    expect(info!.data.length).toBe(10 * 1024); // base chunk
    // header stored sha256(wire) at offset 33..65
    expect(info!.data.subarray(33, 65)).toEqual(HAWK_IDENTITY);
  });

  test("step 2 — store_wire verifies sha256 + stashes wire", async () => {
    // 1024-byte wire payload + 1 vector meta + 1 signer = ~1228 bytes
    // legacy. No CU bump needed (just sha256 + memcpy, ~3 k CU).
    const ix = createHawk512StoreWire(HAWK_KP.publicKey);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(ix),
      [feePayer]
    );

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).not.toBeNull();
    expect(info!.data.length).toBe(10 * 1024); // still base size — finalize resizes
    // Stashed wire pubkey lives at PREPARED_OFFSET (header 33 + hash 32 +
    // pad 7 = 72) and stays there until finalize overwrites with the
    // prepared form.
    expect(
      Buffer.from(info!.data.subarray(33 + 32 + 7, 33 + 32 + 7 + 1024))
    ).toEqual(Buffer.from(HAWK_KP.publicKey));
  });

  test("step 3 — finalize resizes + writes prepared blob", async () => {
    // `prepare_into` draws ~410 k CU on the live validator — over the
    // 200 k per-tx default — so the finalize tx ships with an explicit CU
    // bump.
    const cuBump = ComputeBudgetProgram.setComputeUnitLimit({ units: 600_000 });
    const finalizeIx = createHawk512Finalize(HAWK_KP.publicKey);
    await sendAndConfirmTransaction(
      connection,
      new Transaction().add(cuBump, finalizeIx),
      [feePayer]
    );

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).not.toBeNull();
    expect(info!.data.length).toBe(33 + 32 + 7 + 18464); // 18536 — full
    // Prepared region (after the 7-byte pad) is no longer all-zero.
    const prepared = info!.data.subarray(33 + 32 + 7);
    expect(prepared.some((b) => b !== 0)).toBe(true);

    const account = await fetchVectorAccount(connection, HAWK512, HAWK_IDENTITY);
    expect(account.bump).toBe(vectorBump);
    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionHawk512(
      HAWK_KP,
      currentNonce,
      [cuIx],
      [],
      feePayer.address
    );

    const tx = new Transaction().add(cuIx, advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      HAWK512,
      currentNonce,
      HAWK_IDENTITY,
      [cuIx],
      [],
      feePayer.address
    );

    const account = await fetchVectorAccount(connection, HAWK512, HAWK_IDENTITY);
    expect(Buffer.from(account.nonce)).toEqual(Buffer.from(currentNonce));
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      HAWK512,
      HAWK_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, pre, post) =>
        signAdvanceInstructionHawk512(
          HAWK_KP,
          nonce,
          pre,
          post,
          feePayer.address
        ),
      [cuIx]
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
      HAWK512,
      HAWK_IDENTITY,
      feePayer.address,
      withdrawAmount
    );
    const passthroughIx = createPassthroughInstruction(
      HAWK512,
      HAWK_IDENTITY,
      [withdrawSub]
    );
    const advanceIx = signAdvanceInstructionHawk512(
      HAWK_KP,
      currentNonce,
      [cuIx],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(cuIx, advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      HAWK512,
      currentNonce,
      HAWK_IDENTITY,
      [cuIx],
      [passthroughIx],
      feePayer.address
    );

    const after = await connection.getAccountInfo(vectorPda);
    expect(after).not.toBeNull();
    expect(Number(after!.lamports)).toBe(
      Number(startingLamports) - Number(withdrawAmount)
    );
  });

  test("close hawk512 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      HAWK512,
      HAWK_IDENTITY,
      feePayer.address
    );
    const passthroughIx = createPassthroughInstruction(
      HAWK512,
      HAWK_IDENTITY,
      [closeSub]
    );
    const advanceIx = signAdvanceInstructionHawk512(
      HAWK_KP,
      currentNonce,
      [cuIx],
      [passthroughIx],
      feePayer.address
    );
    const tx = new Transaction().add(cuIx, advanceIx, passthroughIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});
