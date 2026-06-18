import { describe, test, expect } from "vitest";
import { Address, SystemProgram, Transaction } from "@solana/web3.js";
import {
  Vector,
  falcon512Keygen,
  hawk512Keygen,
  serializeArtifact,
  deserializeArtifact,
  decodeOps,
  summarize,
  verifyArtifact,
  review,
} from "../src/index.js";

const KEY = new Uint8Array(32);
KEY[31] = 0x11;
const A = new Address("11111111111111111111111111111112");
const B = new Address("11111111111111111111111111111113");
const NONCE = new Uint8Array(32).fill(2);
const v = Vector.ed25519(KEY); // no feePayer → digest is feePayer-independent
const transfer = SystemProgram.transfer({ fromPubkey: A, toPubkey: B, lamports: 5 });

describe("serialize", () => {
  test("round-trips stably", () => {
    const art = v.authorize(NONCE, transfer);
    const j1 = serializeArtifact(art);
    const j2 = serializeArtifact(deserializeArtifact(j1));
    expect(j2).toBe(j1);
  });
});

describe("decodeOps + summarize", () => {
  test("decodes the CPI and renders a System transfer", () => {
    const art = v.authorize(NONCE, transfer);
    const ops = decodeOps(art);
    expect(ops.length).toBe(1);
    expect(ops[0].programId.toBase58()).toBe(SystemProgram.programId.toBase58());
    expect(summarize(art)[0]).toContain("System transfer");
    expect(summarize(art)[0]).toContain("5");
  });

  test("empty op (revocation) decodes to nothing", () => {
    const art = v.authorize(NONCE, []);
    expect(decodeOps(art).length).toBe(0);
  });
});

describe("verifyArtifact", () => {
  test("accepts a correctly signed artifact", () => {
    const art = v.authorize(NONCE, transfer);
    expect(verifyArtifact(art)).toBe(true);
  });

  test("rejects a tampered op", () => {
    const art = v.authorize(NONCE, transfer);
    // mutate the passthrough payload → digest no longer matches the signature
    const data = art.instructions[1].data;
    data[data.length - 1] ^= 0xff;
    expect(verifyArtifact(art)).toBe(false);
  });
});

describe("verifyArtifact with a fee payer", () => {
  test("verifies an artifact whose digest binds the fee payer", () => {
    const feePayer = new Address("11111111111111111111111111111119");
    const vf = Vector.ed25519(KEY, { feePayer });
    // op references the fee payer → exercises message-flag promotion in the digest
    const op = SystemProgram.transfer({ fromPubkey: feePayer, toPubkey: B, lamports: 9 });
    const art = vf.authorize(NONCE, op);
    expect(art.feePayer?.toBase58()).toBe(feePayer.toBase58());
    expect(verifyArtifact(art)).toBe(true);
  });
});

describe("verifyArtifact across schemes", () => {
  const secpKey = new Uint8Array(32);
  secpKey[31] = 7;
  const op = SystemProgram.transfer({ fromPubkey: A, toPubkey: B, lamports: 5 });

  test("ed25519", () => {
    expect(verifyArtifact(Vector.ed25519(KEY).authorize(NONCE, op))).toBe(true);
  });
  test("secp256k1", () => {
    expect(verifyArtifact(Vector.secp256k1(secpKey).authorize(NONCE, op))).toBe(true);
  });
  test("eip191", () => {
    expect(verifyArtifact(Vector.eip191(secpKey).authorize(NONCE, op))).toBe(true);
  });
  test("falcon512 carries the wire pubkey and verifies", () => {
    const art = Vector.falcon512(falcon512Keygen()).authorize(NONCE, op);
    expect(art.publicKey).toBeDefined();
    expect(verifyArtifact(art)).toBe(true);
  });
  test("hawk512 carries the wire pubkey and verifies (advance after compute budget)", () => {
    const art = Vector.hawk512(hawk512Keygen()).authorize(NONCE, op);
    expect(art.publicKey).toBeDefined();
    expect(art.advanceIndex).toBe(1); // compute-budget pre-instruction
    expect(verifyArtifact(art)).toBe(true);
  });
  test("tamper is rejected (secp256k1)", () => {
    const art = Vector.secp256k1(secpKey).authorize(NONCE, op);
    const data = art.instructions[1].data;
    data[data.length - 1] ^= 0xff;
    expect(verifyArtifact(art)).toBe(false);
  });
});

describe("verifyArtifact unknown scheme", () => {
  test("throws for an unknown program id", () => {
    const fake = {
      programId: new Address("11111111111111111111111111111111"), // not a Vector scheme
      identity: new Uint8Array(32),
      nonce: new Uint8Array(32),
      nextNonce: new Uint8Array(32),
      advanceIndex: 0,
      instructions: [],
      transaction: () => new Transaction(),
    } as any;
    expect(() => verifyArtifact(fake)).toThrow();
  });
});

describe("review", () => {
  test("renders a deterministic block", () => {
    const art = v.authorize(NONCE, transfer);
    const text = review(art);
    expect(text).toContain("VECTOR ARTIFACT");
    expect(text).toContain("System transfer");
    expect(review(art)).toBe(text);
  });
});
