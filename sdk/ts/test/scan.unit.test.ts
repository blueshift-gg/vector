import { describe, test, expect } from "vitest";
import { Address, Connection } from "@solana/web3.js";
import { scanMigration, TOKEN_PROGRAM_ID } from "../src/index.js";

const owner = new Address("11111111111111111111111111111112");
const pda = new Address("11111111111111111111111111111113");
const TA1 = new Address("11111111111111111111111111111114");
const TA2 = new Address("11111111111111111111111111111115");
const STK = new Address("11111111111111111111111111111116");
const MINT = new Address("11111111111111111111111111111117");

function mintData(authority: Address | null, freeze: Address | null): Uint8Array {
  const d = new Uint8Array(82);
  if (authority) {
    d[0] = 1;
    d.set(authority.toBytes(), 4);
  }
  d[45] = 1; // is_initialized
  if (freeze) {
    d[46] = 1;
    d.set(freeze.toBytes(), 50);
  }
  return d;
}

function mockConn(opts: {
  balance: number;
  tokenAccounts?: Record<string, Address[]>;
  stake?: Record<number, Address[]>;
  accountInfos?: Record<string, Uint8Array>;
}): Connection {
  return {
    getBalance: async (_addr: Address) => opts.balance,
    getTokenAccountsByOwner: async (
      _owner: Address,
      { programId }: { programId: Address }
    ) => ({
      value: (opts.tokenAccounts?.[programId.toBase58()] ?? []).map((pubkey) => ({
        pubkey,
      })),
    }),
    getProgramAccounts: async (_pid: Address, cfg: any) => {
      const offset = cfg.filters[0].memcmp.offset;
      return (opts.stake?.[offset] ?? []).map((pubkey) => ({ pubkey }));
    },
    getAccountInfo: async (addr: Address) => {
      const data = opts.accountInfos?.[addr.toBase58()];
      return data ? { data } : null;
    },
  } as unknown as Connection;
}

describe("scanMigration", () => {
  test("flags everything still on the old key", async () => {
    const conn = mockConn({
      balance: 5_000_000,
      tokenAccounts: { [TOKEN_PROGRAM_ID.toBase58()]: [TA1, TA2] },
      stake: { 44: [STK] }, // withdraw-authority offset
      accountInfos: { [MINT.toBase58()]: mintData(owner, null) },
    });

    const report = await scanMigration(conn, { owner, pda, mints: [MINT] });

    expect(report.complete).toBe(false);
    expect(report.unmigrated.length).toBe(5); // sol + 2 token + stake + mint
    expect(report.unmigrated.some((i) => i.kind === "sol")).toBe(true);
    expect(report.unmigrated.filter((i) => i.kind === "token").length).toBe(2);
    expect(report.unmigrated.some((i) => i.kind === "stake")).toBe(true);
    expect(report.unmigrated.some((i) => i.kind === "mint-authority")).toBe(true);
  });

  test("complete when drained and authority points at the pda", async () => {
    const conn = mockConn({
      balance: 0,
      accountInfos: { [MINT.toBase58()]: mintData(pda, null) },
    });
    const report = await scanMigration(conn, { owner, pda, mints: [MINT] });

    expect(report.complete).toBe(true);
    expect(report.unmigrated.length).toBe(0);
    expect(report.items.find((i) => i.kind === "sol")?.status).toBe("migrated");
    expect(report.items.find((i) => i.kind === "mint-authority")?.status).toBe(
      "migrated"
    );
  });

  test("declared generic account: migrated iff authority is the pda", async () => {
    const ACC = new Address("11111111111111111111111111111118");
    const data = new Uint8Array(40);
    data.set(pda.toBytes(), 8);
    const conn = mockConn({ balance: 0, accountInfos: { [ACC.toBase58()]: data } });

    const report = await scanMigration(conn, {
      owner,
      pda,
      accounts: [{ address: ACC, authorityOffset: 8, label: "config" }],
    });
    expect(report.complete).toBe(true);
    expect(report.items.find((i) => i.kind === "account")?.status).toBe("migrated");
  });
});
