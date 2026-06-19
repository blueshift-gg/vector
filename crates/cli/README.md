# vector (CLI)

Command-line tool for Vector: inspect, review, and verify artifacts offline, and
read nonce state or advance/scan via RPC.

```bash
cargo install --path crates/cli
```

## Offline subcommands (no RPC)

### inspect

Decode an artifact file: one line per instruction.

```bash
vector inspect art.json
```

### review

Print a human-readable sign-off block (program, identity, nonce → next_nonce,
and decoded instruction list).

```bash
vector review art.json
```

### verify

Verify an artifact's signature offline. Exits `0` if valid, `1` if invalid.

```bash
vector verify art.json
echo $?   # 0 = valid, 1 = invalid signature
```

## Online subcommands (RPC)

### nonce

Read the current 32-byte nonce of a Vector PDA, printed as hex.

```bash
vector nonce --url https://api.mainnet-beta.solana.com <pda>
```

### advance

Sign and broadcast an advance (inert heartbeat by default; add `--to` +
`--lamports` for a withdraw). The Vector scheme key (`--signer-seed`) and the
fee-payer (`--keypair`) are independent. Falcon512 is not supported via the CLI
(no seed-based keygen; use the SDK directly).

```bash
vector advance \
  --url https://api.mainnet-beta.solana.com \
  --keypair fee.json \
  --signer-seed <64-char-hex-seed> \
  --scheme ed25519 \
  [--to <destination> --lamports <n>]
```

Supported `--scheme` values: `ed25519`, `secp256k1`, `eip191`, `hawk512`.

### scan

Audit whether an old keypair authority's assets have migrated to a Vector PDA.
Prints `complete: true/false` and lists any unmigrated items.

```bash
vector scan \
  --url https://api.mainnet-beta.solana.com \
  --owner <old-keypair-address> \
  --pda <vector-pda>
```
