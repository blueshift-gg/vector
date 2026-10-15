import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  WINTERNITZ,
  createAdvanceInstruction,
  createRotatingAdvanceInstruction,
  rotatingAdvanceVectorDigest,
  createInitializeWinternitz,
  createPassthroughInstruction,
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
  const passthrough = createPassthroughInstruction(WINTERNITZ, identity, [
    createCloseSubinstruction(WINTERNITZ, identity, receiver),
  ]);
  // The next key follows the discriminator; the signature follows it.
  const signature = new Uint8Array(WINTERNITZ.signatureLen);
  const advance = createRotatingAdvanceInstruction(WINTERNITZ, identity, nextKey, signature);
  expect(Array.from(advance.data.subarray(0, 42))).toEqual([0, ...nextKey]);
  expect(advance.data.length).toBe(1 + 41 + WINTERNITZ.signatureLen);
  expect(() => createAdvanceInstruction(WINTERNITZ, identity, signature)).toThrow();
  for (const length of [40, 42]) {
    expect(() =>
      createRotatingAdvanceInstruction(WINTERNITZ, identity, new Uint8Array(length), signature)
    ).toThrow();
  }
  const digest = rotatingAdvanceVectorDigest(
    WINTERNITZ, new Uint8Array(32).fill(255), identity, nextKey, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "4bbc26aec24171416b8261d2355ed068bb55cd1f1b0c4f2e5fe8f97d481357b6"
  );
});
