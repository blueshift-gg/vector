import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  WINTERNITZ,
  advanceVectorDigest,
  createInitializeWinternitz,
  createPassthroughInstruction,
  createRotatingPassthroughInstruction,
  createCloseSubinstruction,
  findVectorPda,
  vectorAccountLen,
} from "../src/index.js";

test("Winternitz account and rotation digest match Rust", () => {
  // Shared with tests/winternitz.rs; pins the 849-byte signature.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const identity = publicKey;
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(WINTERNITZ, identity);
  expect(pda.toString()).toBe("Er2fQZXAf3ZoVHiDQAgJGReN5qUz2oh6t8qfU3GGSb9Y");
  expect(bump).toBe(255);
  expect(vectorAccountLen(WINTERNITZ)).toBe(109);

  const initialize = createInitializeWinternitz(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([2, WINTERNITZ.id, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeWinternitz(receiver, new Uint8Array(length))).toThrow();
  }

  const nextKey = new Uint8Array(41).fill(7);
  const passthrough = createRotatingPassthroughInstruction(WINTERNITZ, identity, nextKey, [
    createCloseSubinstruction(WINTERNITZ, identity, receiver),
  ]);
  // The next key follows the discriminator.
  expect(Array.from(passthrough.data.subarray(0, 42))).toEqual([1, ...nextKey]);
  expect(() => createPassthroughInstruction(WINTERNITZ, identity, [])).toThrow();
  // A Winternitz key signs once, so there is always a next key.
  expect(() => createRotatingPassthroughInstruction(WINTERNITZ, identity, null, [])).toThrow();
  for (const length of [40, 42]) {
    expect(() =>
      createRotatingPassthroughInstruction(WINTERNITZ, identity, new Uint8Array(length), [])
    ).toThrow();
  }
  const digest = advanceVectorDigest(
    WINTERNITZ, new Uint8Array(32).fill(255), identity, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "2bce9f103929bb5a73dc85a80588ab5f641da32a4190d030ddca28fe2b333210"
  );
});
