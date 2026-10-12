import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  XMSS,
  advanceVectorDigest,
  createInitializeXmss,
  createPassthroughInstruction,
  createRotatingPassthroughInstruction,
  createWithdrawSubinstruction,
  findVectorPda,
  xmssIdentity,
  vectorAccountLen,
} from "../src/index.js";

test("XMSS account and rotation digest match Rust", () => {
  // Shared with tests/xmss.rs; pins the 41-byte key and 1037-byte signature.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const identity = xmssIdentity(publicKey);
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(XMSS, identity);
  expect(pda.toString()).toBe("4kd7ArVtukusWaCpQgEZsqabWcnQbB4KjjwYnHVExk7c");
  expect(bump).toBe(255);
  expect(vectorAccountLen(XMSS)).toBe(107);

  const initialize = createInitializeXmss(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, XMSS.id, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeXmss(receiver, new Uint8Array(length))).toThrow();
  }

  expect(() => findVectorPda(XMSS, publicKey)).toThrow();
  const nextKey = new Uint8Array(41).fill(7);
  const passthrough = createRotatingPassthroughInstruction(XMSS, identity, nextKey, [
    createWithdrawSubinstruction(XMSS, identity, receiver, 1234n),
  ]);
  // The next key follows the discriminator.
  expect(Array.from(passthrough.data.subarray(0, 42))).toEqual([4, ...nextKey]);
  expect(() => createPassthroughInstruction(XMSS, identity, [])).toThrow();
  for (const length of [40, 42]) {
    expect(() =>
      createRotatingPassthroughInstruction(XMSS, identity, new Uint8Array(length), [])
    ).toThrow();
  }
  const digest = advanceVectorDigest(
    XMSS, new Uint8Array(32).fill(255), identity, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "c3f2d8005870766f472e3b42ffcbf9078ee6a57a210e2f5560e4dc0cb423de23"
  );
});
