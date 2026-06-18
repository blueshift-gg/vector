import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { Connection, Keypair, Transaction } from "@solana/web3.js";
import {
  Vector,
  ED25519,
  createWithdrawSubinstruction,
  createFundWalletInstruction,
  scanMigration,
} from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendTx } from "./helpers.js";

const KEY = new Uint8Array(32);
KEY[31] = 0x51;

describe("fund-in-PDA wallet (on-chain)", () => {
  let connection: Connection;
  let feePayer: Keypair;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("PDA holds SOL and spends it via an offline-signed artifact", async () => {
    const v = Vector.ed25519(KEY, { feePayer: feePayer.address });
    await sendTx(
      connection,
      new Transaction()
        .add(v.initialize(feePayer.address))
        .add(createFundWalletInstruction(feePayer.address, v.pda, 5_000_000)),
      [feePayer]
    );

    const nonce = await v.nonce(connection);
    const before = (await connection.getAccountInfo(v.pda))!.lamports;

    const withdraw = createWithdrawSubinstruction(ED25519, v.identity, feePayer.address, 1_000n);
    const art = v.authorize(nonce, withdraw);
    await sendTx(connection, art.transaction(), [feePayer]);

    const after = (await connection.getAccountInfo(v.pda))!.lamports;
    expect(Number(before) - Number(after)).toBe(1_000);
    expect(Buffer.from(await v.nonce(connection))).toEqual(Buffer.from(art.nextNonce));
  });

  test("scanMigration runs against real RPC and flags the old key's SOL", async () => {
    const v = Vector.ed25519(KEY);
    // Scanning the funded fee payer exercises getBalance / getTokenAccountsByOwner
    // / getProgramAccounts against the live validator (shape validation).
    const report = await scanMigration(connection, { owner: feePayer.address, pda: v.pda });
    expect(report.complete).toBe(false);
    expect(report.items.find((i) => i.kind === "sol")?.status).toBe("unmigrated");
  });
});
