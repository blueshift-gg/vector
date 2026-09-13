import { expect, test } from "vitest";
import { Address, TransactionInstruction } from "@solana/web3.js";
import { createPassthroughInstruction, ED25519, findVectorPda } from "../src/index.js";

test("passthrough preserves external signers", () => {
  const identity = new Uint8Array(32).fill(7);
  const [pda] = findVectorPda(ED25519, identity);
  const cosigner = new Address(new Uint8Array(32).fill(8));
  const nested = new TransactionInstruction({
    programId: new Address(new Uint8Array(32).fill(9)),
    keys: [
      { pubkey: pda, isSigner: true, isWritable: false },
      { pubkey: cosigner, isSigner: true, isWritable: true },
    ],
    data: new Uint8Array(),
  });
  const outer = createPassthroughInstruction(ED25519, identity, [nested]);
  expect(outer.keys.slice(3)).toEqual([
    { pubkey: pda, isSigner: false, isWritable: false },
    { pubkey: cosigner, isSigner: true, isWritable: true },
  ]);
  expect(nested.keys.every((meta) => meta.isSigner)).toBe(true);
});
