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

`Vector.ed25519` is implemented today. The protocol also ships secp256k1,
EIP-191 (Ethereum wallets), and post-quantum Falcon-512 / Hawk-512 programs with
the identical instruction set; their facade constructors follow the same shape.
