/**
 * Migration scanner — audit everything an old keypair authority still controls
 * vs. the target Vector PDA, so an institution can prove (before the durable-
 * nonce deprecation cutoff) that nothing was left behind.
 *
 * Auto-discovers what Solana can be queried by authority — native SOL, SPL +
 * Token-2022 accounts, stake accounts. Mint/freeze authorities and arbitrary
 * program authorities are NOT indexed by authority, so you declare those and
 * the scanner verifies each one points at the PDA.
 */
import { Address, Connection } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID } from "./wallet.js";

const STAKE_PROGRAM_ID = new Address(
  "Stake11111111111111111111111111111111111111"
);

export type AuthorityKind =
  | "sol"
  | "token"
  | "token2022"
  | "stake"
  | "mint-authority"
  | "freeze-authority"
  | "account";

/** One audited item: an account the old authority did or did not migrate. */
export interface ScanItem {
  kind: AuthorityKind;
  /** Base58 address of the controlled account (or the old wallet, for SOL). */
  address: string;
  status: "migrated" | "unmigrated";
  detail?: string;
}

export interface MigrationReport {
  owner: string;
  pda: string;
  /** True iff nothing controllable remains on the old authority. */
  complete: boolean;
  items: ScanItem[];
  /** Convenience: just the items still on the old key — your to-do list. */
  unmigrated: ScanItem[];
}

export interface ScanOptions {
  /** The old keypair authority being migrated away from. */
  owner: Address;
  /** The target Vector PDA authority should now point at. */
  pda: Address;
  /** Mints to check (mint + freeze authority) — not discoverable by authority. */
  mints?: Address[];
  /** Generic accounts: verify the 32-byte authority at `authorityOffset`. */
  accounts?: {
    address: Address;
    authorityOffset: number;
    kind?: AuthorityKind;
    label?: string;
  }[];
  /** SOL balance (lamports) at/below which `owner` counts as drained. Default 0. */
  dustLamports?: number;
}

function pubkeyAt(data: Uint8Array, offset: number): string {
  return new Address(data.slice(offset, offset + 32)).toBase58();
}

/**
 * Audit the migration of `owner` → `pda`. `complete` is true iff nothing
 * controllable remains on `owner`. Run it, migrate `report.unmigrated`,
 * re-run until complete.
 */
export async function scanMigration(
  connection: Connection,
  opts: ScanOptions
): Promise<MigrationReport> {
  const owner = opts.owner.toBase58();
  const pda = opts.pda.toBase58();
  const items: ScanItem[] = [];

  // 1. Native SOL.
  const balance = await connection.getBalance(opts.owner);
  if (balance > (opts.dustLamports ?? 0)) {
    items.push({
      kind: "sol",
      address: owner,
      status: "unmigrated",
      detail: `${balance} lamports still on the old key`,
    });
  } else {
    items.push({ kind: "sol", address: owner, status: "migrated" });
  }

  // 2. SPL + Token-2022 accounts owned by the old key.
  for (const [programId, kind] of [
    [TOKEN_PROGRAM_ID, "token"],
    [TOKEN_2022_PROGRAM_ID, "token2022"],
  ] as const) {
    const res = await connection.getTokenAccountsByOwner(opts.owner, { programId });
    for (const { pubkey } of res.value) {
      items.push({
        kind,
        address: pubkey.toBase58(),
        status: "unmigrated",
        detail: "token account still owned by the old key",
      });
    }
  }

  // 3. Stake accounts where the old key is staker or withdraw authority.
  const seenStake = new Set<string>();
  for (const [offset, role] of [
    [12, "stake authority"],
    [44, "withdraw authority"],
  ] as const) {
    const accts = (await connection.getProgramAccounts(STAKE_PROGRAM_ID, {
      filters: [{ memcmp: { offset, bytes: owner } }],
      dataSlice: { offset: 0, length: 0 },
    } as any)) as unknown as { pubkey: Address }[];
    for (const { pubkey } of accts) {
      const addr = pubkey.toBase58();
      if (seenStake.has(addr)) continue;
      seenStake.add(addr);
      items.push({
        kind: "stake",
        address: addr,
        status: "unmigrated",
        detail: `old key is the ${role}`,
      });
    }
  }

  // 4. Declared mints — mint authority (COption @0/@4) + freeze (@46/@50).
  for (const mint of opts.mints ?? []) {
    const info = await connection.getAccountInfo(mint);
    if (!info) continue;
    const data = new Uint8Array(info.data);
    if (data[0] === 1) {
      const auth = pubkeyAt(data, 4);
      items.push({
        kind: "mint-authority",
        address: mint.toBase58(),
        status: auth === pda ? "migrated" : "unmigrated",
        detail: auth === pda ? undefined : `mint authority is ${auth}`,
      });
    }
    if (data.length >= 82 && data[46] === 1) {
      const auth = pubkeyAt(data, 50);
      items.push({
        kind: "freeze-authority",
        address: mint.toBase58(),
        status: auth === pda ? "migrated" : "unmigrated",
        detail: auth === pda ? undefined : `freeze authority is ${auth}`,
      });
    }
  }

  // 5. Declared generic accounts — authority at a given offset.
  for (const a of opts.accounts ?? []) {
    const info = await connection.getAccountInfo(a.address);
    if (!info) continue;
    const auth = pubkeyAt(new Uint8Array(info.data), a.authorityOffset);
    items.push({
      kind: a.kind ?? "account",
      address: a.address.toBase58(),
      status: auth === pda ? "migrated" : "unmigrated",
      detail:
        (a.label ? a.label + ": " : "") +
        (auth === pda ? "authority is the PDA" : `authority is ${auth}`),
    });
  }

  const unmigrated = items.filter((i) => i.status === "unmigrated");
  return { owner, pda, complete: unmigrated.length === 0, items, unmigrated };
}
