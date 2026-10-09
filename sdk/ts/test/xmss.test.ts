import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  XMSS,
  advanceVectorDigest,
  createInitializeXmss,
  createPassthroughInstruction,
  createRotateSubinstruction,
  createWithdrawSubinstruction,
  findVectorPda,
  xmssIdentity,
  vectorAccountLen,
} from "../src/index.js";

test("XMSS account and rotation digest match Rust", () => {
  // Shared with tests/xmss.rs; pins the 41-byte identity and 1037-byte carve-out.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const identity = xmssIdentity(publicKey);
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(XMSS, identity);
  expect(pda.toString()).toBe("Er2fQZXAf3ZoVHiDQAgJGReN5qUz2oh6t8qfU3GGSb9Y");
  expect(bump).toBe(255);
  expect(vectorAccountLen(XMSS)).toBe(107);

  const initialize = createInitializeXmss(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, XMSS.id, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeXmss(receiver, new Uint8Array(length))).toThrow();
  }

  expect(() => findVectorPda(XMSS, publicKey)).toThrow();
  const rotate = createRotateSubinstruction(XMSS, identity, new Uint8Array(41).fill(7));
  expect(Array.from(rotate.data)).toEqual([5, ...new Uint8Array(41).fill(7)]);
  expect(rotate.keys).toEqual([{ pubkey: pda, isSigner: false, isWritable: true }]);
  for (const length of [40, 42]) {
    expect(() => createRotateSubinstruction(XMSS, identity, new Uint8Array(length))).toThrow();
  }
  const passthrough = createPassthroughInstruction(XMSS, identity, [
    rotate,
    createWithdrawSubinstruction(XMSS, identity, receiver, 1234n),
  ]);
  const digest = advanceVectorDigest(
    XMSS, new Uint8Array(32).fill(255), identity, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "8d65ff44dca8a074d4f703314c98b5374e8f4977773682d0b08227a831040336"
  );
});
