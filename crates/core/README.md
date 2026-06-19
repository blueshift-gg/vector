# vector-core

Offline-signed Solana transaction builder that replaces durable-nonce workflows.
You sign work against a Vector account's hashchain; a relayer broadcasts it later
with a fresh blockhash and its own fee payer. The signed payload can't be altered
in transit, and the chain is forward-secure — pre-signed steps can't be reordered,
skipped, or partially replayed. Each signing scheme is its own on-chain program;
identity is the pubkey/address for curve-based schemes and `sha256(wire pubkey)`
for the post-quantum ones. Signing is fully sync and works air-gapped.

```toml
[dependencies]
vector-core = "0.1"                          # ed25519 + secp256k1 + eip191 by default
# vector-core = { version = "0.1", features = ["falcon512", "hawk512"] }  # post-quantum
```

## Feature flags

| Feature | Default | Crypto dep | Notes |
| :-- | :--: | :-- | :-- |
| `ed25519` | yes | `ed25519-dalek` | |
| `secp256k1` | yes | `k256` | |
| `eip191` | yes | `k256` + `sha3` | Ethereum `personal_sign` compatible |
| `falcon512` | no | `pqcrypto-falcon`, `pqcrypto-traits` | Post-quantum |
| `hawk512` | no | `hawk512` | Post-quantum |

## Quickstart

```rust
use vector_core::{Ed25519, Op, Vector, serialize_artifact, verify_artifact};

// Build a Vector from a scheme signer.
let v = Vector::new(Ed25519::from_seed(&seed));

// Fetch the current nonce from chain (the only online step), then sign offline.
let art = v.authorize(&nonce, Op::Inert);   // inert advance (revoke / heartbeat)

// Serialize to JSON wire format (TS SDK compatible) and hand off to a relayer.
let json = serialize_artifact(&art);

// Verify the artifact's signature offline (no RPC needed).
assert!(verify_artifact(&art).unwrap());
```

## Strategies

```rust
// CHAIN — ordered, forward-secure (each op signed against the previous next_nonce)
let steps: Vec<Artifact> = v.chain(&nonce, &[Op::One(withdraw_ix), Op::Inert]);

// BRANCH — mutually exclusive arms; landing one orphans the rest atomically
use std::collections::BTreeMap;
let mut arms = BTreeMap::new();
arms.insert("settle".into(), Op::One(pay_ix));
arms.insert("cancel".into(), Op::Inert);
let branches: BTreeMap<String, Artifact> = v.branch(&nonce, arms);

// DERIVE — independent sub-accounts (own key + PDA, same API)
let sub = v.derive(0);
```

## Built-in ops

```rust
v.withdraw(&nonce, &destination, lamports);  // SOL transfer via passthrough CPI
v.close(&nonce, &destination);               // close + reclaim rent
v.register(&payer);                          // Vec<Vec<Instruction>> (multi-tx for PQ)
v.initialize(&payer);                        // single Instruction (curve schemes only)
```

## Artifact transport + offline inspection

```rust
// JSON wire (TS-compatible): serialize / deserialize
let json = serialize_artifact(&art);
let art2 = deserialize_artifact(&json).unwrap();

// Human-readable inspection
let lines: Vec<String> = summarize(&art);    // one decoded line per instruction
let block: String = review(&art);            // full VECTOR ARTIFACT sign-off block
```

## Signing schemes

| Feature | Identity | Notes |
| :-- | :-- | :-- |
| `ed25519` | 32-byte pubkey | deterministic |
| `secp256k1` | 33-byte compressed pubkey | |
| `eip191` | 20-byte Ethereum address | any ETH personal_sign wallet |
| `falcon512` | `sha256(wire pubkey)` | post-quantum lattice |
| `hawk512` | `sha256(wire pubkey)` | post-quantum lattice, deterministic |
