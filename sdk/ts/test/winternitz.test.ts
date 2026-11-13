import { expect, test } from "vitest";
import { PublicKey } from "@solana/web3.js";
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
  const receiver = new PublicKey(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(WINTERNITZ, identity);
  expect(pda.toString()).toBe("Er2fQZXAf3ZoVHiDQAgJGReN5qUz2oh6t8qfU3GGSb9Y");
  expect(bump).toBe(255);
  expect(vectorAccountLen(WINTERNITZ)).toBe(117);

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
  // After the discriminator: validUntil (u64 LE, here never), the next key,
  // then the signature.
  const signature = new Uint8Array(WINTERNITZ.signatureLen);
  const advance = createRotatingAdvanceInstruction(WINTERNITZ, identity, nextKey, signature);
  expect(Array.from(advance.data.subarray(0, 50))).toEqual([0, ...new Array(8).fill(255), ...nextKey]);
  expect(advance.data.length).toBe(1 + 8 + 41 + WINTERNITZ.signatureLen);
  expect(createRotatingAdvanceInstruction(WINTERNITZ, identity, nextKey, signature, 77n).data.subarray(1, 9)).toEqual(
    Uint8Array.of(77, 0, 0, 0, 0, 0, 0, 0)
  );
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
    "c9cbb58a103bb4ddd2626e8d942d1abc4b722413f6a9b47db8f562d33c7b5116"
  );
});
