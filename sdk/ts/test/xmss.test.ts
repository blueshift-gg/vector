import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  XMSS,
  advanceVectorDigest,
  createInitializeXmss,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  findVectorPda,
  vectorAccountLen,
} from "../src/index.js";

test("XMSS account and withdrawal digest match Rust", () => {
  // Shared with tests/xmss.rs; pins the 41-byte identity and 1037-byte carve-out.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(XMSS, publicKey);
  expect(pda.toString()).toBe("FVsCnwNqcdFb2EU6B6rK3UsJEQEDZPTgZoqvT1LrJYZ5");
  expect(bump).toBe(255);
  expect(vectorAccountLen(XMSS)).toBe(74);

  const initialize = createInitializeXmss(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeXmss(receiver, new Uint8Array(length))).toThrow();
  }

  const passthrough = createPassthroughInstruction(XMSS, publicKey, [
    createWithdrawSubinstruction(XMSS, publicKey, receiver, 1234n),
  ]);
  const digest = advanceVectorDigest(
    XMSS, new Uint8Array(32).fill(255), publicKey, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "0c249997a3405d591f9a180ffc466215c83dd51946a56c4e46356417c680a347"
  );
});
