import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { Address, Connection, Keypair, SystemProgram, Transaction } from "@solana/web3.js";
import { Vector, hawk512Keygen } from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendTx } from "./helpers.js";

// Distinct keys so this suite never collides with the per-scheme tests.
const CHAIN_KEY = new Uint8Array(32);
CHAIN_KEY[31] = 0x42;
const BRANCH_KEY = new Uint8Array(32);
BRANCH_KEY[31] = 0x43;
const ROOT_KEY = new Uint8Array(32);
ROOT_KEY[31] = 0x44;

describe("Vector (front door, on-chain)", () => {
  let connection: Connection;
  let feePayer: Keypair;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("chain enforces order (forward-secrecy)", async () => {
    const v = Vector.ed25519(CHAIN_KEY, { feePayer: feePayer.address });
    await sendTx(
      connection,
      new Transaction().add(v.initialize(feePayer.address)),
      [feePayer]
    );

    const nonce = await v.nonce(connection);
    const ops = v.chain(nonce, [[], []]); // two inert advances, ordered

    // Step 1 cannot land before step 0 (signed against a future nonce).
    await expect(sendTx(connection, ops[1].transaction(), [feePayer])).rejects.toThrow();
    await sendTx(connection, ops[0].transaction(), [feePayer]);
    await sendTx(connection, ops[1].transaction(), [feePayer]);

    expect(Buffer.from(await v.nonce(connection))).toEqual(Buffer.from(ops[1].nextNonce));
  });

  test("branch is mutually exclusive (sign two, execute one)", async () => {
    const v = Vector.ed25519(BRANCH_KEY, { feePayer: feePayer.address });
    await sendTx(
      connection,
      new Transaction().add(v.initialize(feePayer.address)),
      [feePayer]
    );

    const nonce = await v.nonce(connection);
    const pay = (lamports: number) =>
      SystemProgram.transfer({
        fromPubkey: feePayer.address,
        toPubkey: feePayer.address,
        lamports,
      });
    const { settle, cancel } = v.branch(nonce, { settle: pay(1), cancel: pay(2) });

    await sendTx(connection, settle.transaction(), [feePayer]);
    await expect(sendTx(connection, cancel.transaction(), [feePayer])).rejects.toThrow();
  });

  test("derived sub-accounts advance independently", async () => {
    const root = Vector.ed25519(ROOT_KEY, { feePayer: feePayer.address });
    const a = root.derive(0);
    const b = root.derive(1);

    // deterministic + distinct
    expect(root.derive(0).pda.toBase58()).toBe(a.pda.toBase58());
    expect(a.pda.toBase58()).not.toBe(b.pda.toBase58());

    await sendTx(
      connection,
      new Transaction().add(
        a.initialize(feePayer.address),
        b.initialize(feePayer.address)
      ),
      [feePayer]
    );

    const na = await a.nonce(connection);
    const nb = await b.nonce(connection);
    await sendTx(connection, a.authorize(na, []).transaction(), [feePayer]); // advance a only

    expect(Buffer.from(await a.nonce(connection))).not.toEqual(Buffer.from(na)); // a moved
    expect(Buffer.from(await b.nonce(connection))).toEqual(Buffer.from(nb)); // b untouched
  });

  // Non-ed25519 schemes verify on-chain through the same facade.
  const SCHEMES = [
    { name: "secp256k1", last: 0x61, make: (k: Uint8Array, o: { feePayer: Address }) => Vector.secp256k1(k, o) },
    { name: "eip191", last: 0x62, make: (k: Uint8Array, o: { feePayer: Address }) => Vector.eip191(k, o) },
  ];
  for (const s of SCHEMES) {
    test(`${s.name}: facade init + authorize advances on-chain`, async () => {
      const key = new Uint8Array(32);
      key[31] = s.last;
      const v = s.make(key, { feePayer: feePayer.address });
      await sendTx(connection, new Transaction().add(v.initialize(feePayer.address)), [feePayer]);
      const nonce = await v.nonce(connection);
      const art = v.authorize(nonce, []); // inert advance
      await sendTx(connection, art.transaction(), [feePayer]);
      expect(Buffer.from(await v.nonce(connection))).toEqual(Buffer.from(art.nextNonce));
    });
  }

  test("hawk512: 3-tx registration + advance on-chain", async () => {
    const v = Vector.hawk512(hawk512Keygen(), { feePayer: feePayer.address });
    // register() returns one group per transaction (initialize / storeWire / finalize)
    for (const group of v.register(feePayer.address)) {
      await sendTx(connection, new Transaction().add(...group), [feePayer]);
    }
    const nonce = await v.nonce(connection);
    const art = v.authorize(nonce, []); // inert advance; carries the compute-budget pre
    await sendTx(connection, art.transaction(), [feePayer]);
    expect(Buffer.from(await v.nonce(connection))).toEqual(Buffer.from(art.nextNonce));
  }, 60_000);
});
