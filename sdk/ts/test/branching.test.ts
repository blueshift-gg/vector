import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  Connection,
  Keypair,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import {
  ED25519,
  fetchVectorAccount,
  createInitializeEd25519,
  ed25519ChainSigner,
  signChain,
  signBranches,
  deriveEd25519LaneSet,
  laneChainSigner,
} from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendTx } from "./helpers.js";

// Distinct keys so this suite never collides with the per-scheme tests.
const CHAIN_KEY = new Uint8Array(32);
CHAIN_KEY[31] = 0x42;
const LANE_MASTER = new Uint8Array(32).fill(0x5b);

describe("vector-branching", () => {
  let connection: Connection;
  let feePayer: Keypair;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("ordered chain enforces sequence (forward-secrecy)", async () => {
    const signer = ed25519ChainSigner(CHAIN_KEY);
    await sendTx(
      connection,
      new Transaction().add(createInitializeEd25519(feePayer.address, signer.identity)),
      [feePayer]
    );
    const { nonce } = await fetchVectorAccount(connection, ED25519, signer.identity);
    const chain = signChain(signer, nonce, [{}, {}], feePayer.address);

    const submit = (s: (typeof chain)[number]) =>
      sendTx(connection, new Transaction().add(...s.pre, s.advanceIx, ...s.post), [feePayer]);

    // Step 1 cannot land before step 0 (signed against a future nonce).
    await expect(submit(chain[1])).rejects.toThrow();
    // In order: step 0 then step 1 both succeed.
    await submit(chain[0]);
    await submit(chain[1]);

    const after = await fetchVectorAccount(connection, ED25519, signer.identity);
    expect(Buffer.from(after.nonce)).toEqual(Buffer.from(chain[1].nextNonce));
  });

  test("branches are mutually exclusive (sign two, execute one)", async () => {
    const key = new Uint8Array(32);
    key[31] = 0x43;
    const signer = ed25519ChainSigner(key);
    await sendTx(
      connection,
      new Transaction().add(createInitializeEd25519(feePayer.address, signer.identity)),
      [feePayer]
    );
    const { nonce } = await fetchVectorAccount(connection, ED25519, signer.identity);

    // Two distinct branches from the same state (different post ixs).
    const post = (lamports: number) => ({
      post: [
        SystemProgram.transfer({
          fromPubkey: feePayer.address,
          toPubkey: feePayer.address,
          lamports,
        }),
      ],
    });
    const branches = signBranches(
      signer,
      nonce,
      [
        { label: "settle", steps: [post(1)] },
        { label: "cancel", steps: [post(2)] },
      ],
      feePayer.address
    );

    const submit = (b: (typeof branches)[number]) =>
      sendTx(
        connection,
        new Transaction().add(...b.steps[0].pre, b.steps[0].advanceIx, ...b.steps[0].post),
        [feePayer]
      );

    // Execute "settle"; "cancel" is now orphaned (parent nonce consumed).
    await submit(branches[0]);
    await expect(submit(branches[1])).rejects.toThrow();
  });

  test("lanes advance independently (non-exclusive parallelism)", async () => {
    const lanes = deriveEd25519LaneSet(LANE_MASTER, 2);
    await sendTx(
      connection,
      new Transaction().add(
        ...lanes.map((l) => createInitializeEd25519(feePayer.address, l.identity))
      ),
      [feePayer]
    );

    for (const lane of lanes) {
      const signer = laneChainSigner(lane);
      const { nonce } = await fetchVectorAccount(connection, ED25519, lane.identity);
      const [step] = signChain(signer, nonce, [{}], feePayer.address);
      await sendTx(connection, new Transaction().add(step.advanceIx), [feePayer]);
    }

    const a = await fetchVectorAccount(connection, ED25519, lanes[0].identity);
    const b = await fetchVectorAccount(connection, ED25519, lanes[1].identity);
    expect(Buffer.from(a.nonce)).not.toEqual(Buffer.from(b.nonce));
  });
});
