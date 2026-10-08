// Regenerate mainnet-active-features.txt with `bun tests/fixtures/mainnet-features.mjs`:
// the features active on mainnet-beta among those the test runtime's
// `agave-feature-set` knows. A feature is active when its account is owned by
// the Feature program and holds `Some(activation slot)`.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const RPC = 'https://api.mainnet-beta.solana.com';
const FEATURE_PROGRAM = 'Feature111111111111111111111111111111111111';

const { packages } = JSON.parse(execFileSync(
  'cargo', ['metadata', '--format-version', '1', '--locked'],
  { cwd: new URL('..', import.meta.url), maxBuffer: 1 << 28 },
));
const crate = packages.find(p => p.name === 'agave-feature-set');
const source = readFileSync(join(dirname(crate.manifest_path), 'src/lib.rs'), 'utf8');
const candidates = [...new Set(source.match(/(?<=")[1-9A-HJ-NP-Za-km-z]{32,44}(?=")/g))].sort();

const active = [];
for (let start = 0; start < candidates.length; start += 100) {
  const batch = candidates.slice(start, start + 100);
  const response = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'getMultipleAccounts',
      params: [batch, { encoding: 'base64' }],
    }),
  });
  const accounts = (await response.json()).result.value;
  accounts.forEach((account, i) => {
    // bincode `Feature { activated_at: Option<u64> }`
    if (account?.owner === FEATURE_PROGRAM && Buffer.from(account.data[0], 'base64')[0] === 1)
      active.push(batch[i]);
  });
}

writeFileSync(
  new URL('mainnet-active-features.txt', import.meta.url),
  `# agave-feature-set ${crate.version}: ${active.length} of ${candidates.length} candidate ids active on mainnet-beta.\n`
    + active.map(key => `${key}\n`).join(''),
);
console.log(`${active.length} active`);
