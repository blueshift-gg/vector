import { describe, test, expect } from "vitest";
import { Address, SystemProgram, Transaction } from "@solana/web3.js";
import {
  Vector,
  ED25519,
  ed25519Identity,
  findVectorPda,
  ADVANCE_DISCRIMINATOR,
  PASSTHROUGH_DISCRIMINATOR,
  INITIALIZE_DISCRIMINATOR,
} from "../src/index.js";

const KEY = new Uint8Array(32);
KEY[31] = 0x11;
const PAY = new Address("11111111111111111111111111111112");
const NONCE = new Uint8Array(32).fill(2);
const ix = (lamports: number) =>
  SystemProgram.transfer({ fromPubkey: PAY, toPubkey: PAY, lamports });

describe("Vector construction", () => {
  test("binds identity + pda", () => {
    const v = Vector.ed25519(KEY);
    expect(Buffer.from(v.identity)).toEqual(Buffer.from(ed25519Identity(KEY)));
    const [pda] = findVectorPda(ED25519, v.identity);
    expect(v.pda.toBase58()).toBe(pda.toBase58());
  });

  test("initialize targets the pda", () => {
    const v = Vector.ed25519(KEY);
    const i = v.initialize(PAY);
    expect(i.data[0]).toBe(INITIALIZE_DISCRIMINATOR);
    expect(i.keys[1].pubkey.toBase58()).toBe(v.pda.toBase58());
  });
});

describe("authorize", () => {
  const v = Vector.ed25519(KEY, { feePayer: PAY });

  test("single op → [advance, passthrough] artifact", () => {
    const art = v.authorize(NONCE, ix(1));
    expect(art.instructions.length).toBe(2);
    expect(art.instructions[0].data[0]).toBe(ADVANCE_DISCRIMINATOR);
    expect(art.instructions[1].data[0]).toBe(PASSTHROUGH_DISCRIMINATOR);
    expect(Buffer.from(art.nonce)).toEqual(Buffer.from(NONCE));
    expect(art.transaction()).toBeInstanceOf(Transaction);
  });

  test("op accepts an array of CPIs in one passthrough", () => {
    const art = v.authorize(NONCE, [ix(1), ix(2)]);
    expect(art.instructions.length).toBe(2); // still [advance, one passthrough]
    expect(art.instructions[1].data[0]).toBe(PASSTHROUGH_DISCRIMINATOR);
  });

  test("empty op is an inert advance (revocation): advance only", () => {
    const art = v.authorize(NONCE, []);
    expect(art.instructions.length).toBe(1);
    expect(art.instructions[0].data[0]).toBe(ADVANCE_DISCRIMINATOR);
  });
});

describe("chain", () => {
  const v = Vector.ed25519(KEY, { feePayer: PAY });
  test("ops are chained: each starts where the previous ended", () => {
    const arts = v.chain(NONCE, [ix(1), ix(2), []]);
    expect(arts.length).toBe(3);
    expect(Buffer.from(arts[0].nonce)).toEqual(Buffer.from(NONCE));
    expect(Buffer.from(arts[1].nonce)).toEqual(Buffer.from(arts[0].nextNonce));
    expect(Buffer.from(arts[2].nonce)).toEqual(Buffer.from(arts[1].nextNonce));
  });
});

describe("branch", () => {
  const v = Vector.ed25519(KEY, { feePayer: PAY });
  test("alternatives share the parent nonce, diverge after", () => {
    const { settle, cancel } = v.branch(NONCE, { settle: ix(10), cancel: [] });
    expect(Buffer.from(settle.nonce)).toEqual(Buffer.from(NONCE));
    expect(Buffer.from(cancel.nonce)).toEqual(Buffer.from(NONCE));
    expect(Buffer.from(settle.nextNonce)).not.toEqual(Buffer.from(cancel.nextNonce));
  });
});

describe("derive", () => {
  test("sub-accounts are deterministic and distinct", () => {
    const v = Vector.ed25519(KEY);
    expect(v.derive(0).pda.toBase58()).toBe(v.derive(0).pda.toBase58());
    expect(v.derive(0).pda.toBase58()).not.toBe(v.derive(1).pda.toBase58());
    expect(v.derive(0).pda.toBase58()).not.toBe(v.pda.toBase58());
  });
});

describe("status", () => {
  const v = Vector.ed25519(KEY, { feePayer: PAY });
  const arts = v.chain(NONCE, [ix(1), ix(2)]);
  test("pending / completed / orphaned", () => {
    expect(v.status(arts, arts[0].nonce)).toEqual({ state: "pending", nextStepIndex: 0 });
    expect(v.status(arts, arts[1].nextNonce)).toEqual({ state: "completed" });
    expect(v.status(arts, new Uint8Array(32).fill(0xff))).toEqual({ state: "orphaned" });
  });
});
