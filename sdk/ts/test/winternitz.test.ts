import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  WINTERNITZ,
  advanceVectorDigest,
  createInitializeWinternitz,
  createPassthroughInstruction,
  createRotateSubinstruction,
  createCloseSubinstruction,
  findVectorPda,
  winternitzIdentity,
  vectorAccountLen,
} from "../src/index.js";

test("Winternitz account and rotation digest match Rust", () => {
  // Shared with tests/winternitz.rs; pins the 849-byte signature carve-out.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const identity = winternitzIdentity(publicKey);
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(WINTERNITZ, identity);
  expect(pda.toString()).toBe("8DgkUyaVWAvj24nWMEdFec11GfzhZ5CpoAFwdojVmt9R");
  expect(bump).toBe(255);
  expect(vectorAccountLen(WINTERNITZ)).toBe(106);

  const initialize = createInitializeWinternitz(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeWinternitz(receiver, new Uint8Array(length))).toThrow();
  }

  expect(() => findVectorPda(WINTERNITZ, publicKey)).toThrow();
  const rotate = createRotateSubinstruction(WINTERNITZ, identity, new Uint8Array(41).fill(7));
  expect(Array.from(rotate.data)).toEqual([5, ...new Uint8Array(41).fill(7)]);
  expect(rotate.keys).toEqual([{ pubkey: pda, isSigner: false, isWritable: true }]);
  for (const length of [40, 42]) {
    expect(() => createRotateSubinstruction(WINTERNITZ, identity, new Uint8Array(length))).toThrow();
  }
  const passthrough = createPassthroughInstruction(WINTERNITZ, identity, [
    rotate,
    createCloseSubinstruction(WINTERNITZ, identity, receiver),
  ]);
  const digest = advanceVectorDigest(
    WINTERNITZ, new Uint8Array(32).fill(255), identity, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "4167456091e49e9a6f6b2b29a485c1b3e138de90002e16df6330812a8884c541"
  );
});
