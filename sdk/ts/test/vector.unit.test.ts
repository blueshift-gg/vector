import { describe, test, expect } from "vitest";
import { Address, SystemProgram, Transaction } from "@solana/web3.js";
import {
  Vector,
  ED25519,
  SECP256K1,
  EIP191,
  FALCON512,
  ed25519Identity,
  secp256k1Identity,
  eip191Identity,
  falcon512Identity,
  falcon512Keygen,
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

describe("withdraw / close", () => {
  const v = Vector.ed25519(KEY, { feePayer: PAY });
  const to = new Address("11111111111111111111111111111119");

  test("withdraw builds a passthrough'd withdraw artifact", () => {
    const art = v.withdraw(NONCE, to, 1000n);
    expect(art.instructions.length).toBe(2);
    expect(art.instructions[0].data[0]).toBe(ADVANCE_DISCRIMINATOR);
    expect(art.instructions[1].data[0]).toBe(PASSTHROUGH_DISCRIMINATOR);
  });

  test("close builds a passthrough'd close artifact", () => {
    const art = v.close(NONCE, to);
    expect(art.instructions.length).toBe(2);
    expect(art.instructions[1].data[0]).toBe(PASSTHROUGH_DISCRIMINATOR);
  });
});

describe("multi-scheme facade", () => {
  const secpKey = new Uint8Array(32);
  secpKey[31] = 7; // valid secp256k1 scalar

  test("secp256k1 binds compressed-pubkey identity + signs", () => {
    const v = Vector.secp256k1(secpKey, { feePayer: PAY });
    expect(v.scheme.programId.toBase58()).toBe(SECP256K1.programId.toBase58());
    expect(Buffer.from(v.identity)).toEqual(Buffer.from(secp256k1Identity(secpKey)));
    expect(v.pda.toBase58()).toBe(findVectorPda(SECP256K1, v.identity)[0].toBase58());
    const art = v.authorize(NONCE, ix(1));
    expect(art.instructions[0].data[0]).toBe(ADVANCE_DISCRIMINATOR);
    expect(art.instructions[0].data.length).toBe(1 + SECP256K1.signatureLen); // 65
  });

  test("eip191 binds the 20-byte ETH address identity + signs (65-byte sig)", () => {
    const v = Vector.eip191(secpKey, { feePayer: PAY });
    expect(v.scheme.programId.toBase58()).toBe(EIP191.programId.toBase58());
    expect(v.identity.length).toBe(20);
    expect(Buffer.from(v.identity)).toEqual(Buffer.from(eip191Identity(secpKey)));
    const art = v.authorize(NONCE, ix(1));
    expect(art.instructions[0].data.length).toBe(1 + EIP191.signatureLen); // 1 + 65
  });

  test("falcon512 binds sha256(wire) identity; derive throws", () => {
    const kp = falcon512Keygen();
    const v = Vector.falcon512(kp, { feePayer: PAY });
    expect(v.scheme.programId.toBase58()).toBe(FALCON512.programId.toBase58());
    expect(Buffer.from(v.identity)).toEqual(Buffer.from(falcon512Identity(kp.publicKey)));
    const art = v.authorize(NONCE, ix(1));
    expect(art.instructions[0].data.length).toBe(1 + FALCON512.signatureLen); // 1 + 666
    expect(() => v.derive(0)).toThrow();
  });

  test("secp256k1 derive yields deterministic, distinct sub-accounts", () => {
    const v = Vector.secp256k1(secpKey);
    expect(v.derive(0).pda.toBase58()).toBe(v.derive(0).pda.toBase58());
    expect(v.derive(0).pda.toBase58()).not.toBe(v.derive(1).pda.toBase58());
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
