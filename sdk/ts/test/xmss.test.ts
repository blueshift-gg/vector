import { expect, test } from "vitest";
import { PublicKey } from "@solana/web3.js";
import {
  XMSS,
  createAdvanceInstruction,
  createRotatingAdvanceInstruction,
  rotatingAdvanceVectorDigest,
  createInitializeXmss,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  findVectorPda,
  vectorAccountLen,
} from "../src/index.js";

test("XMSS account and rotation digest match Rust", () => {
  // Shared with tests/xmss.rs; pins the 41-byte key and 1037-byte signature.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const identity = publicKey;
  const receiver = new PublicKey(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(XMSS, identity);
  expect(pda.toString()).toBe("4kd7ArVtukusWaCpQgEZsqabWcnQbB4KjjwYnHVExk7c");
  expect(bump).toBe(255);
  expect(vectorAccountLen(XMSS)).toBe(121);

  const initialize = createInitializeXmss(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([2, XMSS.id, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeXmss(receiver, new Uint8Array(length))).toThrow();
  }

  const nextKey = new Uint8Array(41).fill(7);
  const passthrough = createPassthroughInstruction(XMSS, identity, [
    createWithdrawSubinstruction(XMSS, identity, receiver, 1234n),
  ]);
  // After the discriminator: validUntil (u64 LE, here never), the next key,
  // then the signature.
  const signature = new Uint8Array(XMSS.signatureLen);
  const advance = createRotatingAdvanceInstruction(XMSS, identity, nextKey, signature);
  expect(Array.from(advance.data.subarray(0, 50))).toEqual([0, ...new Array(8).fill(255), ...nextKey]);
  expect(advance.data.length).toBe(1 + 8 + 41 + XMSS.signatureLen);
  expect(createRotatingAdvanceInstruction(XMSS, identity, nextKey, signature, 77n).data.subarray(1, 9)).toEqual(
    Uint8Array.of(77, 0, 0, 0, 0, 0, 0, 0)
  );
  expect(() => createAdvanceInstruction(XMSS, identity, signature)).toThrow();
  for (const length of [40, 42]) {
    expect(() =>
      createRotatingAdvanceInstruction(XMSS, identity, new Uint8Array(length), signature)
    ).toThrow();
  }
  const digest = rotatingAdvanceVectorDigest(
    XMSS, new Uint8Array(32).fill(255), identity, nextKey, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "1d69cda6a40727c8acb398e7318dc67bae02be16b796d4c8031acbbbe22e99a8"
  );
});
