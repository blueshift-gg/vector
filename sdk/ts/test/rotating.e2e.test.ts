/**
 * Winternitz and XMSS against a validator: rotation, the XMSS leaf counter,
 * and the program's refusals. Each digest is checked with the offline
 * verifier before it is sent.
 *
 * Signing here uses `@blueshift-gg/solana-winternitz/hazmat` keys, which
 * pick the leaf by hand and record nothing: the tests choose each leaf, and
 * never sign one twice. Real signers use the package's persistent
 * `SigningKey` (Bun), which records a leaf as used before it signs.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import * as hazmat from "@blueshift-gg/solana-winternitz/hazmat";
import {
  WINTERNITZ,
  XMSS,
  VECTOR_HEADER_LEN,
  VectorError,
  RotatingState,
  createInitializeWinternitz,
  createInitializeXmss,
  createCloseSubinstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  fetchVectorAccount,
  findVectorPda,
  signAdvanceInstructionWinternitz,
  signAdvanceInstructionXmss,
  verifyAdvanceSignature,
  RejectedError,
} from "../src/index.js";
import { RPC_URL, WS_URL, FEE_PAYER_SEED, sendTx } from "./helpers.js";

const fill = (bytes: Uint8Array) => {
  crypto.getRandomValues(bytes);
};

/** A hazmat key as a signer at one chosen leaf. */
const at = (key: { signAt(leaf: number, message: Uint8Array, random: typeof fill): any }, leaf: number) => ({
  sign: (message: Uint8Array) => key.signAt(leaf, message, fill),
});

/** The key and XMSS leaf counter the account holds now. */
async function onChain(connection: Connection, pda: PublicKey): Promise<RotatingState> {
  const data = (await connection.getAccountInfo(pda))!.data;
  const key = Uint8Array.from(data.subarray(VECTOR_HEADER_LEN, VECTOR_HEADER_LEN + 41));
  const rest = data.subarray(VECTOR_HEADER_LEN + 41);
  return rest.length === 4
    ? { key, nextLeaf: new DataView(rest.buffer, rest.byteOffset, 4).getUint32(0, true) }
    : { key };
}

/** The program's custom error code in a failed transaction's message. */
const custom = (code: VectorError) => new RegExp(`custom program error: 0x${code.toString(16)}\\b|"Custom":${code}\\b`);

describe("vector-rotating", () => {
  let connection: Connection;
  let feePayer: Keypair;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, { commitment: "confirmed", wsEndpoint: WS_URL });
    feePayer = await Keypair.fromSeed(FEE_PAYER_SEED);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("Winternitz rotates every signature and never closes", async () => {
    const keys = [0, 1, 2, 3].map(() => hazmat.winternitz.SecretKey.generate(fill));
    const pub = keys.map((key) => key.verifyingKey().toBytes());
    const identity = pub[0];
    const [pda] = findVectorPda(WINTERNITZ, identity);
    await sendTx(
      connection,
      [
        createInitializeWinternitz(feePayer.publicKey, identity),
        SystemProgram.transfer({ fromPubkey: feePayer.publicKey, toPubkey: pda, lamports: 5_000_000 })
      ],
      [feePayer]
    );

    // Key 0 withdraws and hands over to key 1; key 1 hands over to key 2.
    for (const [signer, withdraw] of [
      [0, true],
      [1, false],
    ] as const) {
      const { nonce } = await fetchVectorAccount(connection, WINTERNITZ, identity);
      const post = withdraw
        ? [
            createPassthroughInstruction(WINTERNITZ, identity, [
              createWithdrawSubinstruction(WINTERNITZ, identity, feePayer.publicKey, 1_000n),
            ]),
          ]
        : [];
      const advance = signAdvanceInstructionWinternitz(
        at(keys[signer], 0),
        identity,
        nonce,
        pub[signer + 1],
        [],
        post,
        feePayer.publicKey
      );
      const signature = advance.data.subarray(1 + 8 + 41);
      const digest = verifyAdvanceSignature(
        { scheme: WINTERNITZ, identity, nextKey: pub[signer + 1], current: await onChain(connection, pda) },
        nonce,
        [],
        post,
        signature,
        feePayer.publicKey
      );
      await sendTx(connection, [advance, ...post], [feePayer]);
      expect((await fetchVectorAccount(connection, WINTERNITZ, identity)).nonce).toEqual(digest);
      expect((await onChain(connection, pda)).key).toEqual(pub[signer + 1]);
    }

    const { nonce } = await fetchVectorAccount(connection, WINTERNITZ, identity);
    // Key 2's one signature: a close, which the program refuses.
    const close = createPassthroughInstruction(WINTERNITZ, identity, [
      createCloseSubinstruction(WINTERNITZ, identity, feePayer.publicKey),
    ]);
    const advance = signAdvanceInstructionWinternitz(
      at(keys[2], 0),
      identity,
      nonce,
      pub[3],
      [],
      [close],
      feePayer.publicKey
    );
    await expect(
      sendTx(connection, [advance, close], [feePayer])
    ).rejects.toThrow(custom(VectorError.KeyRotates));
    expect((await onChain(connection, pda)).key).toEqual(pub[2]);
    expect(await connection.getAccountInfo(pda)).not.toBeNull();
  });

  // An XMSS advance is over 1,232 bytes on its own (a 1,037-byte signature
  // and a 41-byte next key): it only fits a V1 transaction.
  test("XMSS keeps its key across leaves, refuses a used one, and rotates", async () => {
    const first = hazmat.xmss.SecretKey.generate(fill);
    const second = hazmat.xmss.SecretKey.generate(fill);
    const identity = first.verifyingKey().toBytes();
    const next = second.verifyingKey().toBytes();
    const [pda] = findVectorPda(XMSS, identity);
    await sendTx(
      connection,
      [
        createInitializeXmss(feePayer.publicKey, identity),
        SystemProgram.transfer({ fromPubkey: feePayer.publicKey, toPubkey: pda, lamports: 5_000_000 })
      ],
      [feePayer]
    );

    const advance = async (
      key: typeof first,
      leaf: number,
      nextKey: Uint8Array,
      post: ReturnType<typeof createPassthroughInstruction>[] = []
    ) => {
      const { nonce } = await fetchVectorAccount(connection, XMSS, identity);
      const ix = signAdvanceInstructionXmss(at(key, leaf), identity, nonce, nextKey, [], post, feePayer.publicKey);
      return { ix, nonce, signature: ix.data.subarray(1 + 8 + 41), post };
    };
    const check = async (a: Awaited<ReturnType<typeof advance>>, nextKey: Uint8Array) =>
      verifyAdvanceSignature(
        { scheme: XMSS, identity, nextKey, current: await onChain(connection, pda) },
        a.nonce,
        [],
        a.post,
        a.signature,
        feePayer.publicKey
      );

    // Leaf 0 keeps the key; the counter moves to 1.
    let a = await advance(first, 0, identity);
    await check(a, identity);
    await sendTx(connection, [a.ix], [feePayer]);
    expect(await onChain(connection, pda)).toEqual({ key: identity, nextLeaf: 1 });

    // Leaves may be skipped: 3 signs, and 1 and 2 are spent with it.
    a = await advance(first, 3, identity);
    await check(a, identity);
    await sendTx(connection, [a.ix], [feePayer]);
    expect(await onChain(connection, pda)).toEqual({ key: identity, nextLeaf: 4 });

    // Leaf 2 is below the counter: the offline verifier and the program
    // both refuse it, before any hashing.
    a = await advance(first, 2, identity);
    await expect(check(a, identity)).rejects.toThrow(RejectedError);
    await expect(sendTx(connection, [a.ix], [feePayer])).rejects.toThrow(
      custom(VectorError.LeafUsed)
    );

    // The last leaf cannot keep the key.
    a = await advance(first, 255, identity);
    await expect(check(a, identity)).rejects.toThrow(RejectedError);
    await expect(sendTx(connection, [a.ix], [feePayer])).rejects.toThrow(
      custom(VectorError.TreeExhausted)
    );

    // Leaf 4 rotates to the second key, with a withdrawal; its counter
    // starts at 0.
    const withdraw = createPassthroughInstruction(XMSS, identity, [
      createWithdrawSubinstruction(XMSS, identity, feePayer.publicKey, 1_000n),
    ]);
    a = await advance(first, 4, next, [withdraw]);
    const digest = await check(a, next);
    await sendTx(connection, [a.ix, withdraw], [feePayer]);
    expect(await onChain(connection, pda)).toEqual({ key: next, nextLeaf: 0 });
    expect((await fetchVectorAccount(connection, XMSS, identity)).nonce).toEqual(digest);

    // The account is still named by the first key; the second signs now.
    a = await advance(second, 0, next);
    await check(a, next);
    await sendTx(connection, [a.ix], [feePayer]);
    expect(await onChain(connection, pda)).toEqual({ key: next, nextLeaf: 1 });
  });
});
