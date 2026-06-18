# Vector TypeScript SDK

Offchain transaction signing for Solana that replaces durable-nonce workflows.
You pre-sign work against a Vector account's hashchain; a relayer broadcasts it
later with a fresh blockhash and its own fee payer. The signed payload can't be
altered in transit, and the chain is **forward-secure** — pre-signed steps can't
be reordered, skipped, or partially replayed.

```bash
bun add vector-sdk        # or npm / pnpm
```

## The front door: `Vector`

A `Vector` is bound once to a signing key. It computes its identity and PDA up
front, and lets you authorize work in terms of plain Solana **instructions** —
the CPIs you want executed under the account's PDA. The SDK wires the `advance`
+ `passthrough` and the transaction layout for you.

```ts
import { Vector } from "vector-sdk";
import { Connection, Keypair, sendAndConfirmTransaction } from "@solana/web3.js";

const connection = new Connection("https://api.devnet.solana.com");
const v = Vector.ed25519(signingKey, { feePayer: relayer.address });

v.identity;  // 32-byte pubkey
v.pda;       // the account's on-chain address
```

### One-time setup

```ts
await sendAndConfirmTransaction(
  connection,
  new Transaction().add(v.initialize(payer.address)),
  [payer]
);
```

### Authorize one action

An **op** is the CPI(s) to run under the PDA — a single instruction or a list:

```ts
const nonce = await v.nonce(connection);          // read current state
const art = v.authorize(nonce, withdrawIx);       // op: Instruction | Instruction[]

// `art` is broadcast-ready; the relayer adds blockhash + signs as fee payer:
await sendAndConfirmTransaction(connection, art.transaction(), [relayer]);
```

An `Artifact` is what every builder returns:

```ts
art.nonce          // the nonce it's bound to (valid only while the PDA sits here)
art.nextNonce      // the nonce after it executes
art.instructions   // [advance] or [advance, passthrough]
art.transaction()  // a fresh Transaction of those instructions
```

## Three strategies

### Sequence — `chain` (ordered, forward-secure)

Each op can only execute after the previous one. Reordering or skipping fails
verification, so a pre-signed batch executes in exactly the order you signed.

```ts
const steps = v.chain(nonce, [opA, opB, opC]);   // Artifact[]
// broadcast steps[0], then steps[1], then steps[2]
```

### Alternatives — `branch` (sign N, execute one)

All branches share one parent state, so whichever lands first orphans the rest
**atomically** — ideal for "settle or cancel" and clean abandonment.

```ts
const { settle, cancel } = v.branch(nonce, {
  settle: paymentIx,
  cancel: [],          // empty op = inert advance (no side effects)
});
await sendAndConfirmTransaction(connection, settle.transaction(), [relayer]);
// `cancel` is now permanently dead.
```

### Parallel — `derive` (independent sub-accounts)

For non-exclusive parallel work (e.g. many simultaneous RFQ positions), derive
sub-accounts. Each is another `Vector` with the same API, its own chain, and a
distinct, deterministic identity/PDA.

```ts
const position0 = v.derive(0);
const position1 = v.derive(1);
await position1.authorize(nonce1, []);   // revoke just position 1
```

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

## Checking validity

```ts
const status = v.status(steps, await v.nonce(connection));
// { state: "pending", nextStepIndex } | { state: "completed" } | { state: "orphaned" }
```

An artifact is broadcastable iff its chain is still at the nonce it was signed
against.

## Inspecting & verifying artifacts

Artifacts are transportable and self-describing — a counterparty or policy
engine can decode the intent and verify the signature **without a chain
connection**.

```ts
import {
  serializeArtifact, deserializeArtifact,
  summarize, verifyArtifact, review,
} from "vector-sdk";

const wire = serializeArtifact(art);     // deterministic JSON for transport
const a = deserializeArtifact(wire);

summarize(a);        // ["System transfer 5 lamports 1111… → 1111…", ...]
verifyArtifact(a);   // true | false — recompute digest + check signature, offline
console.log(review(a));   // deterministic, human-readable block for sign-off
```

`verifyArtifact` covers all four facade schemes (Ed25519, secp256k1, EIP-191,
Falcon-512 — Falcon artifacts carry their wire pubkey); Hawk-512 is
on-chain-verify-only. Unknown programs are rendered raw (program id +
byte/account counts), never silently hidden — so a reviewer always sees the
full intent.

## Migration & the scanner (fund-in-PDA)

The PDA *is* the wallet: hold SOL and tokens in it and spend with offline
artifacts. Move existing holdings in with the migration builders, then **audit
with the scanner** so nothing is left on the old key before the deprecation
cutoff.

```ts
import {
  createMigrateSolInstruction, createPdaAtaInstruction,
  associatedTokenAddress, createSplTransferIx,
  scanMigration,
} from "vector-sdk";

// spend SOL out of the PDA — facade convenience for the program's own withdraw
v.withdraw(nonce, to, 1_000n);

// spend tokens out of the PDA's ATA
const source = associatedTokenAddress(mint, v.pda);
v.authorize(nonce, createSplTransferIx(source, destAta, v.pda, 50n));

// audit: did everything leave the old key?
const report = await scanMigration(connection, {
  owner: oldKey,        // the keypair you're migrating away from
  pda: v.pda,           // the Vector account it should now point at
  mints: [usdcMint],    // declared — mint/freeze authorities aren't queryable by authority
});
if (!report.complete) console.table(report.unmigrated);   // your migration to-do list
```

The scanner **auto-discovers** what Solana can index by authority — native SOL,
SPL + Token-2022 accounts, and stake accounts. Mint/freeze authorities and
arbitrary program authorities are **not** indexed by authority, so you declare
them (`mints`, `accounts`) and the scanner verifies each one points at the PDA.
`report.complete` is true only when nothing controllable remains on the old key.

## Air-gapped signing

Signing is **synchronous and offline** — `authorize`/`chain`/`branch` take a
nonce and never touch the network. Only `nonce()` reads on-chain. For a cold
ceremony: read the nonce online, carry it to the air-gapped signer, sign there,
carry the artifact back out for the relayer to broadcast.

```ts
// online watcher
const nonce = await v.nonce(connection);
// air-gapped signer (no connection)
const art = Vector.ed25519(coldKey, { feePayer }).authorize(nonce, withdrawIx);
```

## Low-level engine

`Vector` is a facade over composable primitives in `vector-sdk/branching`
(`signChain`, `signBranches`, `resolveChainStatus`, `ChainSigner`,
`deriveLaneSeed`) and the instruction builders in `vector-sdk` (`createAdvanceInstruction`,
`createPassthroughInstruction`, `advanceVectorDigest`, …). Reach for these only
when you need control the facade doesn't expose (custom pre/post instructions,
non-Ed25519 schemes, bespoke digest handling).

## Schemes

The facade covers four schemes — same API, different `Vector.*` constructor:

| Constructor | Key material | Identity |
| :-- | :-- | :-- |
| `Vector.ed25519(seed)` | 32-byte Ed25519 seed | 32-byte public key |
| `Vector.secp256k1(privKey)` | 32-byte secp256k1 key | 33-byte compressed pubkey |
| `Vector.eip191(privKey)` | 32-byte secp256k1 key | 20-byte Ethereum address — sign with any `personal_sign` wallet |
| `Vector.falcon512(keypair)` | Falcon-512 keypair | `sha256(wire pubkey)` (post-quantum) |

`derive(i)` works for the 32-byte-key schemes (ed25519 / secp256k1 / eip191);
Falcon sub-accounts are constructed from their own keypairs. **Hawk-512** isn't
on the facade — its registration is a 3-transaction flow (`initialize` →
`storeWire` → `finalize`); use the low-level scheme builders for it.
