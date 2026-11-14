/**
 * `fixtures/vectors.json`, written by reference signers in Rust and checked
 * there by `vectors_are_what_the_program_and_sdk_compute`: one advance
 * signed by every scheme, Ed25519 over a nonce account, with a passthrough
 * and an expiry. The SDK must rebuild every byte of it and accept every
 * signature the program accepts.
 */
import { expect, test } from "vitest";
import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import { readFileSync } from "fs";
import {
  ED25519,
  EIP191,
  FALCON512,
  MLDSA44,
  SECP256K1,
  WINTERNITZ,
  XMSS,
  AdvanceSigner,
  advanceMessage,
  advanceVectorDigest,
  createMultiAdvanceInstruction,
  createPassthroughInstruction,
  createWithdrawSubinstruction,
  findSystemPda,
  findVectorPda,
  rotatingAdvanceVectorDigest,
  signedNonce,
  signerDigest,
  vectorSeed,
  verifyAdvanceSignature,
  verifyAdvanceTransaction,
} from "../src/index.js";

const SCHEMES = [ED25519, EIP191, SECP256K1, FALCON512, MLDSA44, WINTERNITZ, XMSS];

const fixture = JSON.parse(
  readFileSync(new URL("../../../fixtures/vectors.json", import.meta.url), "utf8")
);
const bytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const json = (ix: TransactionInstruction) => ({
  programId: ix.programId.toBase58(),
  keys: ix.keys.map(({ pubkey, isSigner, isWritable }) => ({
    pubkey: pubkey.toBase58(),
    isSigner,
    isWritable,
  })),
  data: hex(ix.data),
});

const validUntil = BigInt(fixture.validUntil);
const feePayer = new PublicKey(fixture.feePayer);
const nonceAccount = new PublicKey(fixture.nonceAccount);
const nonceAccountNonce = bytes(fixture.nonceAccountNonce);
const listed = fixture.signers.map((signer: any, i: number) => ({
  scheme: SCHEMES[i],
  identity: bytes(signer.identity),
  nonce: bytes(signer.nonce),
  nextKey: bytes(signer.nextKey),
  signature: bytes(signer.signature),
  json: signer,
}));
const signers: AdvanceSigner[] = listed.map((s: any) => ({
  scheme: s.scheme,
  identity: s.identity,
  nextKey: s.nextKey,
  ...(s.scheme.id === ED25519.id ? { nonceAccount } : {}),
}));
const signedOver = (s: any) =>
  s.scheme.id === ED25519.id ? signedNonce(nonceAccountNonce, s.nonce) : s.nonce;
const passthrough = createPassthroughInstruction(ED25519, listed[0].identity, [
  createWithdrawSubinstruction(ED25519, listed[0].identity, feePayer, 1_000n),
]);

test("every scheme's account, digest and instruction bytes match Rust", () => {
  expect(listed.map((s: any) => s.json.scheme)).toEqual(SCHEMES.map((s) => s.id));
  expect(json(passthrough)).toEqual(fixture.passthrough);

  const message = advanceMessage(signers, [], [passthrough], feePayer, validUntil);
  expect(hex(message)).toBe(fixture.message);

  for (const s of listed) {
    const [vector, bump] = findVectorPda(s.scheme, s.identity);
    expect(vector.toBase58()).toBe(s.json.vector);
    expect(bump).toBe(s.json.bump);
    expect(hex(vectorSeed(s.identity))).toBe(s.json.seed);
    expect(findSystemPda(vector)[0].toBase58()).toBe(s.json.systemPda);
    expect(hex(signedOver(s))).toBe(s.json.signedOver);
    expect(hex(signerDigest(message, signedOver(s), vector, { nextKey: s.nextKey }))).toBe(
      s.json.digest
    );
    const alone =
      s.scheme.nextKeyLen === 0
        ? advanceVectorDigest(s.scheme, s.nonce, s.identity, [], [passthrough], feePayer)
        : rotatingAdvanceVectorDigest(
            s.scheme,
            s.nonce,
            s.identity,
            s.nextKey,
            [],
            [passthrough],
            feePayer
          );
    expect(hex(alone)).toBe(s.json.aloneDigest);
  }

  const advance = createMultiAdvanceInstruction(
    listed.map((s: any, i: number) => ({ ...signers[i], signature: s.signature })),
    validUntil
  );
  expect(json(advance)).toEqual(fixture.advance);
});

test("the SDK accepts every signature the program accepts", () => {
  const advance = createMultiAdvanceInstruction(
    listed.map((s: any, i: number) => ({ ...signers[i], signature: s.signature })),
    validUntil
  );
  const verified = verifyAdvanceTransaction({
    transaction: [advance, passthrough],
    vectors: listed.map((s: any) => ({ scheme: s.scheme, identity: s.identity, nonce: s.nonce })),
    nonceAccounts: [
      { address: nonceAccount, nonce: nonceAccountNonce, vector: findVectorPda(ED25519, listed[0].identity)[0] },
    ],
    feePayer,
    slot: validUntil,
  });
  expect(verified.signers.map((s) => hex(s.digest))).toEqual(
    listed.map((s: any) => s.json.digest)
  );
  expect(verified.signers.map((s) => s.ok)).toEqual(listed.map(() => true));
  expect(verified.ok).toBe(true);

  // A one-signer check of each, over the same message, fails: the message
  // lists every signer.
  for (const s of listed) {
    expect(() =>
      verifyAdvanceSignature(
        { scheme: s.scheme, identity: s.identity, nextKey: s.nextKey },
        s.nonce,
        [],
        [passthrough],
        s.signature,
        feePayer,
        validUntil
      )
    ).toThrow();
  }

  // Past its expiry, nothing verifies.
  const expired = verifyAdvanceTransaction({
    transaction: [advance, passthrough],
    vectors: listed.map((s: any) => ({ scheme: s.scheme, identity: s.identity, nonce: s.nonce })),
    nonceAccounts: [
      { address: nonceAccount, nonce: nonceAccountNonce, vector: findVectorPda(ED25519, listed[0].identity)[0] },
    ],
    feePayer,
    slot: validUntil + 1n,
  });
  expect(expired.ok).toBe(false);
});
