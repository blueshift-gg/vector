import { describe, test, expect } from "vitest";
import { Address } from "@solana/web3.js";
import { getAssociatedTokenAddressSync } from "@solana/spl-token";
import "./helpers.js"; // applies the Address shim spl-token@0.4 expects
import {
  associatedTokenAddress,
  createSplTransferIx,
  createFundWalletInstruction,
  TOKEN_PROGRAM_ID,
  createMigrateSolInstruction,
  createPdaAtaInstruction,
  createTokenAuthorityReassignment,
} from "../src/index.js";

const PDA = new Address("11111111111111111111111111111113");
const MINT = new Address("So11111111111111111111111111111111111111112");
const PAY = new Address("11111111111111111111111111111112");

describe("wallet", () => {
  test("associatedTokenAddress matches spl-token's off-curve derivation", () => {
    const mine = associatedTokenAddress(MINT, PDA);
    const expected = getAssociatedTokenAddressSync(MINT as any, PDA as any, true);
    expect(mine.toBase58()).toBe(expected.toBase58());
  });

  test("createSplTransferIx encodes Transfer (disc 3, 3 accounts)", () => {
    const ix = createSplTransferIx(PAY, PAY, PDA, 42n);
    expect(ix.programId.toBase58()).toBe(TOKEN_PROGRAM_ID.toBase58());
    expect(ix.data[0]).toBe(3);
    expect(ix.keys.length).toBe(3);
  });

  test("createFundWalletInstruction transfers into the pda", () => {
    const ix = createFundWalletInstruction(PAY, PDA, 1000);
    expect(ix.keys[1].pubkey.toBase58()).toBe(PDA.toBase58());
  });
});

describe("migrate", () => {
  test("migrate SOL transfers old → pda", () => {
    const ix = createMigrateSolInstruction(PAY, PDA, 5);
    expect(ix.keys[0].pubkey.toBase58()).toBe(PAY.toBase58());
    expect(ix.keys[1].pubkey.toBase58()).toBe(PDA.toBase58());
  });

  test("create PDA ATA targets the off-curve ATA owned by the pda", () => {
    const ix = createPdaAtaInstruction(PAY, PDA, MINT);
    expect(ix.keys[1].pubkey.toBase58()).toBe(
      associatedTokenAddress(MINT, PDA).toBase58()
    );
    expect(ix.keys[2].pubkey.toBase58()).toBe(PDA.toBase58());
  });

  test("token authority reassignment is SetAuthority → pda", () => {
    const ix = createTokenAuthorityReassignment(PAY, PAY, PDA);
    expect(ix.data[0]).toBe(6);
  });
});
