import { describe, test, expect } from "vitest";
import { deriveLaneSeed, deriveEd25519Lane, laneChainSigner } from "../src/lanes.js";
import { ED25519, ed25519Identity, findVectorPda } from "../src/index.js";

const MASTER = new Uint8Array(32).fill(0x5a);

describe("lanes", () => {
  test("deriveLaneSeed is deterministic and index-distinct", () => {
    expect(Buffer.from(deriveLaneSeed(MASTER, "ed25519", 0))).toEqual(
      Buffer.from(deriveLaneSeed(MASTER, "ed25519", 0))
    );
    expect(Buffer.from(deriveLaneSeed(MASTER, "ed25519", 0))).not.toEqual(
      Buffer.from(deriveLaneSeed(MASTER, "ed25519", 1))
    );
    expect(() => deriveLaneSeed(MASTER, "ed25519", -1)).toThrow();
  });

  test("each lane has a distinct identity + PDA matching findVectorPda", () => {
    const a = deriveEd25519Lane(MASTER, 0);
    const b = deriveEd25519Lane(MASTER, 1);
    expect(a.pda.toBase58()).not.toBe(b.pda.toBase58());
    const [pda, bump] = findVectorPda(ED25519, a.identity);
    expect(a.pda.toBase58()).toBe(pda.toBase58());
    expect(a.bump).toBe(bump);
    expect(Buffer.from(a.identity)).toEqual(Buffer.from(ed25519Identity(a.signingKey)));
  });

  test("laneChainSigner yields a ChainSigner bound to the lane key", () => {
    const lane = deriveEd25519Lane(MASTER, 2);
    const signer = laneChainSigner(lane);
    expect(Buffer.from(signer.identity)).toEqual(Buffer.from(lane.identity));
  });
});
