import { expect, test } from "vitest";
import { Address, TransactionInstruction } from "@solana/web3.js";
import { readFileSync } from "fs";
import {
  createPassthroughInstruction,
  ED25519,
  EIP191,
  FALCON512,
  findVectorPda,
  MLDSA44,
  SECP256K1,
  VECTOR_HEADER_LEN,
  VectorError,
  WINTERNITZ,
  XMSS,
} from "../src/index.js";

// The program's numbers, pinned by the Rust test
// `the_program_fixture_is_the_programs`.
test("the SDK's numbers are the program's", () => {
  const fixture = JSON.parse(
    readFileSync(new URL("../../../fixtures/program.json", import.meta.url), "utf8")
  );
  expect({
    headerLen: VECTOR_HEADER_LEN,
    schemes: [ED25519, EIP191, SECP256K1, FALCON512, MLDSA44, WINTERNITZ, XMSS],
    errors: Object.fromEntries(
      Object.entries(VectorError).filter(([, code]) => typeof code === "number")
    ),
  }).toEqual(fixture);
});

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
