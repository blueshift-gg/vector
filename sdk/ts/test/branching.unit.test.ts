import { describe, test, expect } from "vitest";
import { Address, SystemProgram } from "@solana/web3.js";
import type { Connection } from "@solana/web3.js";
import {
  signChain,
  signBranches,
  resolveChainStatus,
  whichBranchWon,
  fetchChainStatus,
} from "../src/branching.js";
import {
  ADVANCE_DISCRIMINATOR,
  advanceVectorDigest,
  serializeVectorAccountHeader,
} from "../src/index.js";
import { ED25519, ed25519Identity, ed25519ChainSigner } from "../src/schemes/ed25519.js";

const KEY = new Uint8Array(32);
KEY[31] = 0x07;
const PAY = new Address("11111111111111111111111111111112");
const tx = (lamports: number) => ({
  post: [SystemProgram.transfer({ fromPubkey: PAY, toPubkey: PAY, lamports })],
});

describe("ed25519ChainSigner", () => {
  test("exposes scheme + identity and signs an advance", () => {
    const signer = ed25519ChainSigner(KEY);
    expect(signer.scheme.programId.toBase58()).toBe(ED25519.programId.toBase58());
    expect(Buffer.from(signer.identity)).toEqual(Buffer.from(ed25519Identity(KEY)));

    const nonce = new Uint8Array(32).fill(1);
    const ix = signer.sign(nonce, [], []);
    expect(ix.data[0]).toBe(ADVANCE_DISCRIMINATOR);
    expect(ix.data.length).toBe(1 + ED25519.signatureLen);
  });
});

describe("signChain", () => {
  const signer = ed25519ChainSigner(KEY);
  const start = new Uint8Array(32).fill(2);

  test("chains each step's nonce from the previous nextNonce", () => {
    const chain = signChain(signer, start, [{}, {}, {}]);
    expect(chain.length).toBe(3);
    expect(Buffer.from(chain[0].nonce)).toEqual(Buffer.from(start));
    chain.forEach((s) => {
      const expected = advanceVectorDigest(
        ED25519,
        s.nonce,
        signer.identity,
        s.pre,
        s.post
      );
      expect(Buffer.from(s.nextNonce)).toEqual(Buffer.from(expected));
    });
    expect(Buffer.from(chain[1].nonce)).toEqual(Buffer.from(chain[0].nextNonce));
    expect(Buffer.from(chain[2].nonce)).toEqual(Buffer.from(chain[1].nextNonce));
  });
});

describe("signBranches", () => {
  const signer = ed25519ChainSigner(KEY);
  const parent = new Uint8Array(32).fill(3);

  test("every branch head is signed against the shared parent nonce", () => {
    const branches = signBranches(signer, parent, [
      { label: "settle", steps: [tx(1)] },
      { label: "cancel", steps: [tx(2)] },
    ]);
    expect(branches.map((b) => b.label)).toEqual(["settle", "cancel"]);
    for (const b of branches) {
      expect(Buffer.from(b.steps[0].nonce)).toEqual(Buffer.from(parent));
    }
    expect(Buffer.from(branches[0].steps[0].nextNonce)).not.toEqual(
      Buffer.from(branches[1].steps[0].nextNonce)
    );
  });
});

describe("resolveChainStatus", () => {
  const signer = ed25519ChainSigner(KEY);
  const start = new Uint8Array(32).fill(2);
  const chain = signChain(signer, start, [{}, {}]);

  test("pending at the next unexecuted step", () => {
    expect(resolveChainStatus(chain, chain[0].nonce)).toEqual({
      state: "pending",
      nextStepIndex: 0,
    });
    expect(resolveChainStatus(chain, chain[1].nonce)).toEqual({
      state: "pending",
      nextStepIndex: 1,
    });
  });

  test("completed at the final nextNonce", () => {
    expect(resolveChainStatus(chain, chain[1].nextNonce)).toEqual({
      state: "completed",
    });
  });

  test("orphaned when the on-chain nonce is off this chain", () => {
    expect(resolveChainStatus(chain, new Uint8Array(32).fill(0xff))).toEqual({
      state: "orphaned",
    });
  });
});

describe("whichBranchWon", () => {
  const signer = ed25519ChainSigner(KEY);
  const parent = new Uint8Array(32).fill(3);
  const branches = signBranches(signer, parent, [
    { label: "settle", steps: [tx(1)] },
    { label: "cancel", steps: [tx(2)] },
  ]);

  test("returns the live branch once one has executed", () => {
    const afterSettle = branches[0].steps[0].nextNonce;
    expect(whichBranchWon(branches, afterSettle)?.label).toBe("settle");
  });

  test("returns null while still at the shared parent", () => {
    expect(whichBranchWon(branches, parent)?.label).toBe(undefined);
  });
});

describe("fetchChainStatus", () => {
  const signer = ed25519ChainSigner(KEY);
  const chain = signChain(signer, new Uint8Array(32).fill(2), [{}]);
  const conn = {
    getAccountInfo: async () => ({
      data: serializeVectorAccountHeader({ nonce: chain[0].nonce, bump: 255 }),
    }),
  } as unknown as Connection;

  test("reads the on-chain nonce and resolves status", async () => {
    const status = await fetchChainStatus(conn, signer, chain);
    expect(status).toEqual({ state: "pending", nextStepIndex: 0 });
  });
});
