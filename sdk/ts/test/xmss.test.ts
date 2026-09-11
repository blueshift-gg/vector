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
  expect(pda.toString()).toBe("FVsCnwNqcdFb2EU6B6rK3UsJEQEDZPTgZoqvT1LrJYZ5");
  expect(bump).toBe(255);
  expect(vectorAccountLen(XMSS)).toBe(106);

  const initialize = createInitializeXmss(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, ...publicKey]);
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
    "2b95491cb79d06e9d5f038e2b755375d6582c75839bc3d681afbb1ced1af20da"
  );
});
