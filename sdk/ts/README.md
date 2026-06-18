# Vector TypeScript SDK

Offchain transaction signing for Solana that replaces durable-nonce workflows.
You pre-sign work against a Vector account's hashchain; a relayer broadcasts it
later with a fresh blockhash and its own fee payer. The signed payload can't be
altered in transit, and the chain is **forward-secure** — pre-signed steps can't
be reordered, skipped, or partially replayed.

```bash
bun add vector-sdk        # or npm / pnpm
```

## Import model

The default entrypoint is light — it pulls **no per-scheme crypto**. You
construct a `Vector` from its scheme's subpath, so you only install and bundle
the crypto you actually use. Importing a scheme subpath also registers its
offline verifier with `verifyArtifact`.

| Subpath | Pulls | Constructor |
| :-- | :-- | :-- |
| `vector-sdk/ed25519` | `@noble/curves/ed25519` | `vectorEd25519(seed)` |
| `vector-sdk/secp256k1` | `@noble/curves/secp256k1` | `vectorSecp256k1(privKey)` |
| `vector-sdk/eip191` | `@noble/curves/secp256k1` + keccak | `vectorEip191(privKey)` |
| `vector-sdk/falcon512` | `@noble/post-quantum` | `vectorFalcon512(keypair)` |
| `vector-sdk/hawk512` | `@blueshift-gg/hawk512` | `vectorHawk512(keypair)` |

`identity` is the pubkey/address for ed25519/secp256k1/eip191, and
`sha256(wire pubkey)` for the post-quantum schemes. `eip191` lets you sign with
any Ethereum `personal_sign` wallet. Core (`import … from "vector-sdk"`) gives
you the `Vector` type, inspection, migration, and the scanner; the low-level
chain engine is at `vector-sdk/branching`.

## Quickstart

```ts
import { vectorEd25519 } from "vector-sdk/ed25519";
import { Connection, sendAndConfirmTransaction } from "@solana/web3.js";

const connection = new Connection("https://api.devnet.solana.com");
const v = vectorEd25519(signingKey, { feePayer: relayer.address });

v.identity;  // 32-byte pubkey
v.pda;       // the account's on-chain address

// one-time setup
await sendAndConfirmTransaction(
  connection,
  new Transaction().add(v.initialize(payer.address)),
  [payer]
);

// authorize one action — op = Instruction | Instruction[] (the CPIs to run under the PDA)
const nonce = await v.nonce(connection);          // the only async call
const art = v.authorize(nonce, withdrawIx);
await sendAndConfirmTransaction(connection, art.transaction(), [relayer]);
```

An `Artifact` is what every builder returns: `art.nonce` / `art.nextNonce`,
`art.instructions` (`[...pre, advance, ...passthrough]`), `art.transaction()`,
and `art.advanceIndex` (where the advance sits — 0 except when the scheme
prepends, e.g. Hawk's compute-budget bump).

## Three strategies

```ts
// SEQUENCE — ordered, forward-secure (each op only executes after the prior)
const steps = v.chain(nonce, [opA, opB, opC]);

// ALTERNATIVES — sign N, execute one; the rest orphan atomically
const { settle, cancel } = v.branch(nonce, { settle: paymentIx, cancel: [] }); // [] = inert

// PARALLEL — independent sub-accounts (one per RFQ deal), same API, own chain
const pos0 = v.derive(0);
```

`derive` works for the 32-byte-key schemes (ed25519 / secp256k1 / eip191);
post-quantum sub-accounts are built from their own keypairs.

## Revocation

An empty op (`[]`) is an **inert advance**: it bumps the nonce with no side
effects, invalidating every artifact still outstanding against that nonce.
Unilateral and final.

```ts
await sendAndConfirmTransaction(
  connection,
  v.authorize(await v.nonce(connection), []).transaction(),
  [relayer]
);
```

## Inspecting & verifying artifacts

Artifacts are transportable and self-describing — a counterparty or policy
engine can decode the intent and verify the signature **without a chain
connection**. `verifyArtifact` works for any scheme whose subpath you've
imported (importing `vector-sdk/ed25519` registers Ed25519, etc.).

```ts
import { serializeArtifact, deserializeArtifact, summarize, verifyArtifact, review } from "vector-sdk";
import "vector-sdk/ed25519"; // registers the Ed25519 verifier

const wire = serializeArtifact(art);     // deterministic JSON for transport
const a = deserializeArtifact(wire);

summarize(a);        // ["System transfer 5 lamports 1111… → 1111…", ...]
verifyArtifact(a);   // true | false — recompute digest + check signature, offline
console.log(review(a));   // deterministic, human-readable block for sign-off
```

Verification covers all five schemes (the post-quantum artifacts carry their
wire pubkey). Unknown programs are rendered raw — never silently hidden.

## Migration & the scanner (fund-in-PDA)

The PDA *is* the wallet: hold SOL and tokens in it and spend with offline
artifacts. Move existing holdings in with the migration builders, then **audit
with the scanner** so nothing is left on the old key before the deprecation
cutoff.

```ts
import {
  createMigrateSolInstruction, createPdaAtaInstruction,
  associatedTokenAddress, createSplTransferIx, scanMigration,
} from "vector-sdk";

v.withdraw(nonce, to, 1_000n);                              // spend SOL out of the PDA
const source = associatedTokenAddress(mint, v.pda);
v.authorize(nonce, createSplTransferIx(source, destAta, v.pda, 50n)); // spend tokens

const report = await scanMigration(connection, {
  owner: oldKey,        // the keypair you're migrating away from
  pda: v.pda,
  mints: [usdcMint],    // declared — mint/freeze authorities aren't queryable by authority
});
if (!report.complete) console.table(report.unmigrated);    // your migration to-do list
```

The scanner auto-discovers native SOL, SPL + Token-2022 accounts, and stake
accounts; declared mints/accounts are verified to point at the PDA.
`report.complete` is true only when nothing controllable remains on the old key.

## Registration

`register(payer)` returns the account-creation transactions in order — one
instruction-group per transaction — and is the uniform path across schemes.
Single-transaction schemes return one group (and offer `initialize(payer)` as a
shorthand); **Hawk-512** returns three (`initialize` → `storeWire` →
`finalize`, its prepared pubkey is ~18 KB), and its advance carries a
compute-budget bump committed to by the digest — both handled by the facade.

## Air-gapped signing

Signing is **synchronous and offline** — `authorize` / `chain` / `branch` take
a nonce and never touch the network; only `nonce()` reads on-chain. For a cold
ceremony: read the nonce online, carry it to the air-gapped signer, sign there,
carry the artifact back out for the relayer to broadcast.

```ts
const nonce = await watcher.nonce(connection);             // online
const art = vectorEd25519(coldKey, { feePayer }).authorize(nonce, withdrawIx); // air-gapped
```

## Low-level engine

`Vector` is a facade over composable primitives in `vector-sdk/branching`
(`signChain`, `signBranches`, `resolveChainStatus`, `ChainSigner`,
`deriveLaneSeed`) and the instruction builders in `vector-sdk`
(`createAdvanceInstruction`, `createPassthroughInstruction`,
`advanceVectorDigest`, …). Reach for these only when you need control the
facade doesn't expose (custom pre/post instructions, bespoke digest handling).
```
