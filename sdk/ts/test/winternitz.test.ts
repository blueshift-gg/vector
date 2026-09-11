import { expect, test } from "vitest";
import { Address } from "@solana/web3.js";
import {
  WINTERNITZ,
  advanceVectorDigest,
  createInitializeWinternitz,
  createPassthroughInstruction,
  createCloseSubinstruction,
  findVectorPda,
  vectorAccountLen,
} from "../src/index.js";

test("Winternitz account and close digest match Rust", () => {
  // Shared with tests/winternitz.rs; pins the 849-byte signature carve-out.
  const publicKey = Uint8Array.from({ length: 41 }, (_, i) => i);
  const receiver = new Address(new Uint8Array(32).fill(9));
  const [pda, bump] = findVectorPda(WINTERNITZ, publicKey);
  expect(pda.toString()).toBe("8DgkUyaVWAvj24nWMEdFec11GfzhZ5CpoAFwdojVmt9R");
  expect(bump).toBe(255);
  expect(vectorAccountLen(WINTERNITZ)).toBe(74);

  const initialize = createInitializeWinternitz(receiver, publicKey);
  expect(initialize.keys[1].pubkey.toString()).toBe(pda.toString());
  expect(Array.from(initialize.data)).toEqual([0, ...publicKey]);
  for (const length of [40, 42]) {
    expect(() => createInitializeWinternitz(receiver, new Uint8Array(length))).toThrow();
  }

  const passthrough = createPassthroughInstruction(WINTERNITZ, publicKey, [
    createCloseSubinstruction(WINTERNITZ, publicKey, receiver),
  ]);
  const digest = advanceVectorDigest(
    WINTERNITZ, new Uint8Array(32).fill(255), publicKey, [], [passthrough]
  );
  expect(Buffer.from(digest).toString("hex")).toBe(
    "512c9bf21940276d817dc5395f2e42ed03eac82194ddeb7ad088275f120271ee"
  );
});
