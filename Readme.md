# Vector
Vector is a Solana primitive for offchain transaction signing that can be used in place of durable nonce workflows.

It works by computing a SHA-256 digest of a transaction offchain, signing that digest with one of several supported schemes, and then reproducing the same digest onchain from the instructions sysvar at execution time. The on-chain program verifies the signature before allowing execution to proceed.

This means a Vector account can be controlled by a standard Solana Ed25519 keypair, a plain secp256k1 ECDSA key, an Ethereum (EIP-191) secp256k1 address, or a post-quantum ML-DSA-44, Falcon-512, Winternitz or XMSS key. One program serves every scheme; all of them share the account header and authorization flow. Winternitz and XMSS additionally support key rotation and require persistent signing state.

## Execution Model
A Vector authorization flow proceeds as follows:

1. A transaction is constructed offchain.
2. Its instruction buffer, with the signatures left out, is SHA-256 hashed into a message.
3. The message is hashed again with the current Vector nonce and the account address, and that digest is signed offchain.
4. The transaction is submitted onchain.
5. Vector reads the instruction sysvar, recomputes the same digest, and verifies the signature against it.

If verification succeeds, Vector installs that same digest as its next nonce, creating a history-based hashchain. Any CPIs the signer authorized run in a sibling top-level `Passthrough` instruction in the same transaction (see [Passthrough CPI](#passthrough-cpi)); the digest commits to its exact bytes.

Pre-hashing with SHA-256 keeps the input handed to the on-chain verifier constant-sized regardless of how large the hosting transaction is, which dramatically reduces the work performed inside signature verification.

The fee payer or relayer is therefore not entrusted with authority over transaction contents at any time, as they are unable to alter the authorized transaction buffer without invalidating its corresponding signature.

## Multi-Scheme Support

Vector is one program, `vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV`, serving every signing scheme. It lives in [`programs/vector`](programs/vector/): one file per instruction in [`src/instructions`](programs/vector/src/instructions/), and one file per scheme in [`src/schemes`](programs/vector/src/schemes/). A scheme is one `SigningScheme` impl: its scheme byte, what it stores as the signer's identity, the types of its key, signature and next key, and how it verifies. Every length is the size of one of those types. The instructions are the same for every scheme and reach a scheme only through the `Scheme` table built from that trait. Adding a scheme is a new file and one line in `schemes::scheme`.

| Scheme | Scheme byte | Identity | Signature | On-Chain Identity Storage | Pre-Sign Wrapper |
|--------|------------|----------|-----------|---------------------------|------------------|
| Ed25519    | `1` | 32-byte public key                | 64 bytes `(r, s)`    | 32 B pubkey                          | SHA-256          |
| Secp256k1  | `3` | 33-byte compressed pubkey         | 64 bytes `(r, s)`    | 33 B compressed pubkey               | SHA-256          |
| EIP-191    | `2` | 20-byte ETH address               | 65 bytes `(r, s, v)` | 20 B ETH address                     | EIP-191 + SHA-256|
| Falcon-512 | `4` | 897-byte wire pubkey              | 666 bytes (zero-padded compressed) | 1024 B prepared pubkey | SHA-256 |
| ML-DSA-44 | `5` | 1,312-byte public key | 2,420 bytes | 1,312 B pubkey + 20,544 B prepared key | SHA-256 |
| Winternitz | `6` | 41-byte first public key | 849 bytes | 41 B current key | SHA-256 |
| XMSS | `7` | 41-byte first public key | 1,037 bytes | 41 B current key + 4 B next leaf | SHA-256 |

The scheme byte is a field of the account header and a PDA seed. The program reads it from the account and routes to that scheme, so an account is always handled by the scheme that created it. Only `Initialize`, which has no account yet, takes the byte in its instruction data. Zero is not a scheme, so a zeroed account that someone assigns to the program belongs to none.

### Ed25519
The signer's 32-byte Ed25519 public key is stored directly in the account. The 64-byte `(r, s)` signature is verified directly over the SHA-256 digest. Verification uses [`brine-ed25519`](https://github.com/zfedoran/brine-ed25519) with its `fast-sha512` feature, which keeps Ed25519 advance under ~14k CUs.

### Secp256k1 (plain ECDSA)
A standard secp256k1 ECDSA signer with sec1-compressed public keys. The 33-byte compressed pubkey (`0x02`/`0x03` prefix + 32-byte x-coordinate) is the identity: stored verbatim after the account header and used directly (`> 32` bytes → `sha256`) as the PDA seed. Signatures are 64 bytes `(r, s)` with no recovery byte; verification runs standard ECDSA via the [`solana-secp256k1-ecdsa`](https://crates.io/crates/solana-secp256k1-ecdsa) crate (~72k CUs advance).

This scheme is the natural fit for non-EIP-191 secp256k1 contexts (Bitcoin-style apps, generic crypto libraries) and pairs with anything producing standard ECDSA signatures.

### EIP-191 (Ethereum)
The signer's 20-byte Ethereum address is the identity, stored raw (no padding) after the account header and used directly as the PDA seed.

Signatures are 65 bytes: `r(32) || s(32) || v(1)`, where `v` is the ECDSA recovery ID (0 or 1). Embedding `v` in the instruction data allows on-chain verification with a single `sol_secp256k1_recover` call. The recovery ID is part of the signature, so it is outside the signed message and does not create a circular dependency.

Before signing and recovery, the SHA-256 digest is wrapped in an EIP-191 personal-sign envelope:

```
signed_hash = keccak256("\x19Ethereum Signed Message:\n32" || digest)
```

This means any standard Ethereum wallet that supports `personal_sign` can produce valid Vector signatures. On-chain, the program applies the same EIP-191 wrapping before calling `secp256k1_recover`, then derives the Ethereum address via `keccak256(recovered_pubkey)[12..32]` and compares it against the stored address.

### Falcon-512
Vector supports the post-quantum [Falcon-512](https://falcon-sign.info/) lattice signature scheme via [`solana-falcon512`](https://github.com/blueshift-gg/solana-falcon512), giving forward-secure account control even against an adversary with a cryptographically relevant quantum computer.

Wire pubkeys are 897 bytes, and the wire pubkey is the client identity. Like every scheme, the PDA seed is its SHA-256.

To keep on-chain verification cheap, Vector stores Falcon's *prepared pubkey* (a 1024-byte form with the forward NTT and modular inverse pre-baked) in the account's identity region. The account stores only that prepared form; after the 68-byte header it sits at an even account offset, so the verifier can borrow it zero-copy (a 1024-byte stack copy would overflow the BPF frame). The prepared form is computed once at `initialize` (~60k CUs); subsequent `advance` calls only pay the signature-verify cost (173k–184k CUs, depending on the key and signature).

Falcon signatures are variable-length (compressed Huffman); the wire format zero-pads to 666 bytes so the signature length is constant.

### ML-DSA-44

Vector verifies [ML-DSA-44 (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final) through [`solana-ml-dsa`](https://github.com/blueshift-gg/solana-ml-dsa), using SHAKE128/256 and an empty context. The 1,312-byte public key is the identity and is hashed for the PDA seed. Rust callers supply signatures from an external signer; the TypeScript SDK uses Noble's `ml_dsa44`.

The program prepares the key on chain once, following Falcon's approach. The 21,924-byte account holds the 68-byte header, then `public_key[1312] || prepared_key[20544]`. Registration is three `Initialize` calls: the first creates the account and carries the key, the next two are permissionless and grow it; each allocation grows by at most 10,240 bytes. Account length records progress, and `Advance` rejects incomplete accounts. The public key remains fixed.

Registration takes about 1.1M CU and a subsequent `Advance` about 264K CU in local SBPF tests. Registration and the 2,420-byte signature require [V1 transactions](https://solana.com/upgrades/larger-transaction-sizes); callers supply the transaction limits. The SDK builds instructions and does not submit transactions. The workspace pins `solana-ml-dsa` to a git revision; publish the crate with its required `solana-shake` revision and depend on the release before deploying.

### Winternitz and XMSS

Both schemes use [`solana-winternitz`](https://github.com/blueshift-gg/solana-winternitz): DKKW25 target-sum Winternitz and generalized XMSS with Keccak-256. The one-time instance has an 849-byte signature; the height-8 XMSS instance has a 1,037-byte signature and 256 leaves. Both public keys are 41 bytes. This XMSS variant is not compatible with RFC 8391.

The account is 107 bytes:

```text
nonce[32] || seed[32] || scheme[1] || bump[1] || current_public_key[41]
```

`seed = sha256(first_public_key)` is permanent: it is in the header and in the address. Verification uses `current_public_key`, which can change without moving the account or its assets and authorities. This separation also appears in [Winterwallet's account layout](https://github.com/blueshift-gg/winterwallet/blob/672fc6789b1532ee680f24842d235e0be8737b61/program/src/state.rs).

Both SDKs expose `WINTERNITZ` / `XMSS` and initialization helpers. The identity is the first public key: keep using it for every instruction and digest after rotation. Signing belongs to the caller's persistent signer; the Vector SDKs do not implement signing for these schemes.

### Key rotation

An `Advance` for a Winternitz or XMSS account carries the key that signs next, before the signatures, so the signature covers it. Generate and persist a fresh signer, then authorize its public key with the current signer:

```text
Advance(next_public_key, current-key signature)
Passthrough([...actions])   // optional
```

`create_rotating_advance_instruction` / `createRotatingAdvanceInstruction` builds it, with `rotating_advance_vector_digest` / `rotatingAdvanceVectorDigest` for the digest. Rotation changes only the stored public key; the PDA seed and bump remain fixed. Rotation stays within the account's signing scheme.

The program makes a signature that lands use its key up:

- **Winternitz.** `Advance` replaces the key, and refuses the same key as the next one. A Winternitz account that only co-signs needs nothing but its `Advance`.
- **XMSS.** The account stores the lowest leaf that may sign next. `Advance` refuses a lower leaf and moves the counter past the leaf that signed; a signer may skip leaves. Give the same key to keep it, with its counter; a new key starts again at leaf 0. After the last leaf, the key must change.
- **Listed twice.** An account listed twice is advanced twice, and its second signature must verify against what the first stored: the next Winternitz key, or the XMSS counter past the first leaf. One key cannot sign two digests in one `Advance`.

What the program cannot see is signing off chain. Never sign different authorizations with the same Winternitz key or XMSS leaf: once one of them lands the key or leaf is dead, but until then two signatures are public. The program does not check that a replacement key is fresh, so callers still manage key freshness and persistent signing state. Failed salt sampling and abandoned authorizations consume signing attempts too.

Rotation and actions are atomic. If any instruction fails, the nonce and key changes roll back. Retain the signed authorization and rebroadcast it unchanged when the cause is resolved. A permanently failing action cannot be repaired by changing the transaction and reusing a Winternitz key; this integration has no separate recovery authorization. The Vector nonce prevents replay of successful transactions, but cannot prevent off-chain leaf reuse.

The workspace pins `solana-winternitz` to a git revision. Publish that crate and depend on the release before deploying. Build the program with `cargo build-sbf --manifest-path programs/vector/Cargo.toml`. It is undeployed.

### Digest Construction
Every signer of an `Advance` approves the same message: the instructions sysvar buffer with the `Advance`'s data cut out after its discriminator. Each signer's digest then adds its own next key, so the signatures are the only bytes nobody signs:

```
message = SHA256(buffer[..advance_data_start + 1] || buffer[advance_data_end..])
digest  = SHA256(message || nonce || vector_address || next_key)
```

Each signer signs its own `digest`: the shared message, then its account's current nonce, address and next key (empty for a key that never changes).

Everything else in the buffer — the discriminator, the accounts, CPI payload, surrounding instructions, and sysvar framing — is committed to by the message.

### Several Signers
One `Advance` takes any number of signers, of any schemes:

```
accounts: [vector_1, ..., vector_n, instructions_sysvar]
data:     [0, next_key_1 || sig_1 || ... || next_key_n || sig_n]
```

Any vector may be followed by one of its [nonce accounts](#nonce-accounts); its signature is then over `SHA256(that account's nonce || the vector's nonce)`, and only the nonce account moves.

A next key is present only for an account whose key rotates (Winternitz, XMSS).

The program verifies one signature per account, taking each signature's length from its account's scheme, and advances each nonce. Because each signature is over the whole transaction, every signer approves everything in it, including what the other accounts do. A `Passthrough` is authorised when an earlier `Advance` lists its account; listing an account is only possible with its signature. The `Passthrough` looks for the transaction's first `Advance` before it, wherever a wallet put it. Only one `Advance` can land in a transaction: each one's message covers the other's signatures, so neither can be signed first.

A one-time key (Winternitz, XMSS) should sign last: its signature only lands if every other signer's does, and it must not be used for a second message.

## Instruction Set
Each instruction starts with its discriminator byte.

| Disc | Name        | Top-Level Callable? | Authorisation                                |
|------|-------------|---------------------|----------------------------------------------|
| `0`  | Advance     | **only** top-level (CPI guarded) | offchain signature over the canonical digest |
| `1`  | Passthrough | **only** top-level (CPI guarded) | the first Advance, earlier, lists every signer |
| `2`  | Initialize  | yes | payer funds creation; later calls grow an account too big for one (ML-DSA-44) |
| `3`  | Withdraw    | only via Passthrough reentry | inherited from the authorising Advance       |
| `4`  | Close       | only via Passthrough reentry | inherited from the authorising Advance; with a third account, closes that nonce account of the vector |
| `5`  | InitializeNonce | yes | the nonce account signs, as it does its `CreateAccount`; the vector must exist and not rotate its key |

`Advance` carries the next key of each rotating account, then one signature per account — its handler verifies each, installs the digest as the next nonce (and the next key), and rejects any trailing payload. CPIs under the PDA's signer seeds go in a separate top-level `Passthrough` instruction, whose handler refuses to run unless the first `Advance`, earlier in the transaction, lists every account it signs for. `Close` and `Withdraw` are reachable as top-level instructions in name only — their handlers gate on `vector.is_signer()`, which can only be true when the instruction is reached as a CPI from `Passthrough` (which signs as the PDA via `invoke_signed`). The user authorises any combination of close/withdraw/arbitrary CPIs by signing an `Advance` whose digest commits to the sibling `Passthrough`'s exact bytes. Winterwallet combines key advancement and CPIs in one instruction; Vector keeps `Advance` and `Passthrough` separate.

## Passthrough CPI
Vector acts as a narrow CPI gate in front of ordinary Solana execution. Its role is limited to verifying that the current transaction exactly matches the transaction that was signed offchain against the current Vector state. Once `Advance`'s check succeeds, a sibling top-level `Passthrough` instruction in the same transaction replays its embedded sub-instructions, taking its trailing accounts along with the embedded instruction data and performing CPI actions for the owner. The passthrough handler authorises itself by reading, from the instructions sysvar, the first `Advance` before it and checking it lists every signer — transaction atomicity guarantees that advance verified, or the whole transaction aborted.

After Passthrough CPI, the downstream instruction flow proceeds as normal. As Vector does not alter downstream semantics, it composes naturally with all existing Solana instruction patterns, including those that depend on temporary authority transfer or intra-transaction liquidity, such as flash loans.

Although `passthrough` only replays its own embedded sub-instructions, the digest `advance` verifies covers every top-level instruction in the hosting transaction — including the passthrough's data and account layout. Pre- and post-instructions placed alongside `advance` are committed to by the same signature even though Vector never executes them itself. This is what lets a compute-budget instruction, balance check, or memo coexist with a Vector-authorized payload without weakening the signer's authority — provided they are part of the buffer at signing time; a relayer cannot add them afterwards without invalidating the signature.

### Signers
```
accounts: [instructions_sysvar, vector_1, ..., vector_n, {program, accounts...}...]
data:     [1, n, system_1, ..., system_n, num_ixs, {num_accounts, data_len(u16), data}...]
```

One `Passthrough` signs for up to 16 accounts, each listed in the `Advance`: 16 is the runtime's limit on signers of one call. Each signs as its vector account (`system = 0`) or as its system PDA (`system = 1`); list an account twice to sign as both.

The vector account belongs to the program, so it cannot be the `from` of a System `Transfer`, or `Allocate` and `Assign` like a wallet. Each account therefore has a system PDA, `[vector address, system_bump]` under the program and owned by the System program; `find_system_pda` / `findSystemPda` derives it. The program derives it from the vector's address and stored `system_bump` (about 1,500 CUs), and never takes it from the caller.

For each sub-instruction in the passthrough payload, Vector promotes any account whose address matches one of its signers to `is_signer = true`, and signs with the seeds of those signers only, before invoking. This is what lets `Close`/`Withdraw` pass their `vector.is_signer()` gate when reached via re-entry, and lets arbitrary downstream programs treat the PDA as the signer for authority operations (e.g. SPL Token `set_authority`).

The program never allocates: it runs with pinocchio's `no_allocator!`, and every buffer is on the stack. A sub-instruction therefore takes at most 64 accounts, pinocchio's bound for a call built on the stack.

### Errors
A bad signature is `MissingRequiredSignature`, and every other standard `ProgramError` keeps its meaning. The program's own errors are `ProgramError::Custom(code)`, as `VectorError` in both SDKs:

| Code | Name | When |
|------|------|------|
| `0` | `NotTopLevel` | `Advance` or `Passthrough` ran inside another instruction |
| `1` | `NotAdvanced` | `Passthrough` found no earlier `Advance`, or the first one does not list a signer |
| `2` | `KeyReused` | Winternitz: the next key is the key that just signed |
| `3` | `LeafUsed` | XMSS: the signature's leaf has signed before |
| `4` | `TreeExhausted` | XMSS: the last leaf signed, and the key was not replaced |
| `5` | `ForeignNonce` | `Advance`, `Close`: the nonce account belongs to another vector |
| `6` | `KeyRotates` | `InitializeNonce`: the vector is Winternitz or XMSS |
| `7` | `FreshNonce` | `Advance`, `Close`: the nonce account was created in this slot |

## Security Model
The signer is authorizing a concrete transaction buffer, not a reusable nonce and not a partially specified intent. Since the signed digest is reconstructed from the instruction sysvar onchain, any material change to the transaction changes the digest and invalidates the signature.

This sharply limits relayer authority. A relayer cannot swap programs, rewrite accounts, alter amounts, or append alternative logic while preserving validity. Its role is limited to transport and fee payment.

`Advance` is CPI-guarded (rejects any non-top-level invocation) so a parent program cannot rewrite the sysvar layout the signature was bound to. `Close` and `Withdraw` rely on the runtime's lamport-mutation rules: only the program that owns an account can decrease its balance, so even if an attacker manufactured an `is_signer = true` account, they could not drain a vector PDA they don't own.

## Privacy
Vector never materializes the authorized transaction buffer onchain ahead of execution. Signing is a purely computation over the `(nonce, address, transaction)` tuple. This means the contents of the transaction itself remain private until the moment a relayer pays to submit it.

This sets Vector apart from other onchain signing primitives which typically require onchain transaction buffer accounts — a smart scaling solution, but also an undesirable property for transactions revealing actionable economic data onchain long before it is executed.

## Nonce Progression
Vector advances state by reusing the same SHA-256 digest that was just verified as the next nonce:

```
next_nonce = SHA256(message || current_nonce || vector_address || next_key)
```

where `message` covers the entire instructions sysvar buffer minus the signatures. See [Initialization](#initialization) for the first nonce. Because `current_nonce` is itself an input to the hash, every nonce transition is a deterministic function of both the prior state and the exact transaction being authorized — there is no separate mixing pass.

The signature itself is not used as the state transition input, as ECDSA signatures contain a malleable per-signature ephemeral scalar. Tying the progression to the digest of the current nonce and the current authorized buffer ensures that state advancement is determined by the actual transaction being authorized.

## Invalidation and Forward Exposure
In a monotonically increasing counter-based nonce scheme, all future states are exposed at all times. This can cause security assumptions to break down in interesting, rarely thought about ways. Consider the following scenario:

1. At state N, remove 90% of liquidity from our vault.
2. At state N+1, place all remaining liquidity into escrow.
3. At state N+2, swap the escrowed amount for another token.

If these 3 transactions were securely presigned, but the transaction at state N were to later be replaced with an empty Vector advance instruction, the executed price of the swap in N+2 would be 90% worse.

Vector avoids this breakdown of security assumptions entirely by deriving each Vector state from the current state and the current executed transaction buffer hash. This means each later state depends on the exact prior chain of executions having occurred in order. A state analogous to N+2 cannot become valid unless N+1 has already occurred. Future states are therefore not independently valid, and belong to a deterministic hashchain of all potential midstates.

In addition to reducing exposure to such attacks from N+i to N+1, if at any point the immediate next state, or any chain of future states derived from it are believed to be compromised, it is sufficient to simply advance the Vector state with a single, inert transition. This invalidates every hypothetical future signature derived from the previous nonce, permanently orphaning the entire branch of potential future states.

## Transaction Expiration
Vector only invalidates a signature once the Vector nonce advances. This means signatures revealed in transactions that failed due to transient conditions such as slippage could later become valid and be replayed. Furthermore, a malicious relayer could withold the transaction, waiting until conditions move in their favor, such as a stale quote, a shift in the market market or a liquidation threshold, before submitting.

The mitigation is a small timeout instruction placed as a top-level instruction alongside `advance`. Because the signature commits to the entire instructions sysvar, the timeout is part of the authorized buffer. A minimal program such as [sbpf-asm-timeout](https://github.com/deanmlittle/sbpf-asm-timeout) reads a deadline from its instruction data, reads the current slot or unix timestamp from the clock sysvar, and aborts if the deadline has passed. Any submission attempt after the deadline fails, invalidating the signature.

Vector deliberately remains unopinionated about expiration so users can compose with whatever deadline primitive suits their needs (slot-based, unix-time-based, oracle-based) without bloating the core protocol.

## Relayers and EOAs
Vector constrains a relayer from modifying a user's transaction. It makes no attempt to eliminate the relayer's own trust and custody risks towards the user. Relayers may fail operationally even though Vector's transaction authorization remains intact.

This means that, while Vector is compatible with all EOAs, including those of relayers, it is up to relayers to protect themselves from all forms of operational risks, such as loss of funds, reassignment, or otherwise somehow becoming bricked.

One simple way to mitigate this is to require Vector users to place an ownership and balance check instruction at the end of their transaction. By knowing the balance of a relayer's EOA at the start of a transaction, it is sufficient to simply check that its balance has since increased or remains the same, and that it still belongs to the SystemProgram. This protects relayers by virtue of their right of refusal to sign.

## Account Layout

A Vector account is a PDA at `["vector", [scheme], seed]`, with a fixed 68-byte header followed by the scheme's identity bytes:

```
nonce:    [u8; 32]  // offset  0 — current state nonce
seed:     [u8; 32]  // offset 32 — sha256 of the key the account was created with
scheme:   u8        // offset 64 — scheme byte
bump:     u8        // offset 65 — PDA bump seed
system_bump: u8     // offset 66 — bump of the account's system PDA
pad:      u8        // offset 67 — zero
identity: [u8; N]   // offset 68 — N = stored identity length
```

The system PDA is `[vector address, system_bump]` under the program and belongs to the System program. The pad keeps the identity at a multiple of 4, where Falcon-512 and ML-DSA-44 read their prepared key in place.

A nonce account is a keypair account, as a System nonce account is: 72 bytes, owned by the program:

```
nonce:   [u8; 32]  // offset  0 — the chain's current link
vector:  [u8; 32]  // offset 32 — the vector account whose key signs over it
created: u64       // offset 64 — the slot it was created in
```

No vector account is 72 bytes, so the program tells the two apart by length.

The seed is the SHA-256 of the key given to `Initialize`, for every scheme. It is stored so the account can sign as itself without re-deriving it. For Winternitz/XMSS it is the hash of the first key, also after rotation.

| Scheme      | Total Account Size | Identity Bytes (offset 68)                      |
|-------------|--------------------|-------------------------------------------------|
| Ed25519     | 100 B              | 32 B public key                                 |
| EIP-191     | 88 B               | 20 B ETH address                                |
| Secp256k1   | 101 B              | 33 B compressed pubkey                          |
| Falcon-512  | 1092 B             | 1024 B prepared public key                      |
| ML-DSA-44   | 21,924 B           | 1,312 B public key + 20,544 B prepared key |
| Winternitz | 109 B | 41 B current public key |
| XMSS | 113 B | 41 B current public key + 4 B next leaf (u32 LE) |

Two schemes cannot share a PDA: the scheme byte is one of the seeds, so the same identity bytes derive a different address under each scheme. The header's scheme byte is what the program routes on.

## Initialization
A Vector account is created via the `initialize` instruction, which allocates the `68 + stored_identity_len` byte PDA. Instruction data: `[disc, scheme, ...key]` (the only instruction that carries the scheme byte), where `key` is the identity:

| Scheme      | `key`                     | Stored Identity                              |
|-------------|---------------------------|----------------------------------------------|
| Ed25519     | 32-byte pubkey            | the pubkey verbatim                          |
| EIP-191     | 20-byte ETH address       | the address verbatim                        |
| Falcon-512  | 897-byte wire pubkey      | `prepared[1024]` |
| ML-DSA-44   | 1,312-byte public key     | `pk[1312] \|\| prepared[20544]`, over 3 × `initialize` |
| Secp256k1   | 33-byte compressed pubkey | the compressed pubkey verbatim              |
| Winternitz | 41-byte public key | the current 41-byte key |
| XMSS | 41-byte public key | the current 41-byte key, then the next leaf |

`initialize` allocates the full `68 + stored_identity_len` bytes, and every
scheme but ML-DSA-44 registers in one call. An instruction can grow an account
by at most 10,240 bytes, so ML-DSA-44's first `initialize` creates that much
and two more, with no data, grow and fill the rest; the three fit one
transaction.
An address that already holds lamports can still be initialized: the payer
funds only the shortfall.

For Ed25519, the pubkey must be a valid curve point. For EIP-191, the 20-byte address must be non-zero. For Secp256k1, the compressed pubkey must start with `0x02` or `0x03`. For Falcon-512, the wire pubkey is validated and expanded into the 1024-byte prepared form at init time. For ML-DSA-44, the public key is stored verbatim and expanded across the three `initialize` calls.

The initial nonce is derived entirely onchain using the `sol_get_sysvar` syscall to read the most recent slot hash and height from the `SlotHashes` sysvar: `sha256(seed || latest_slot_entry)`. If an account is closed and the same identity is later re-initialized, the nonce differs, as the slot hash changes in every slot. Replaying a prior signature chain would require the account to be opened, used, closed, reopened and replayed all within the same slot. Do not create and close an account in the same slot.

## Closing and Partial Withdraw
`Close` empties the PDA's lamports into a `close_to` account; the runtime removes an account with no lamports at the end of the transaction. `Withdraw` moves a fixed amount of lamports out; the runtime refuses to leave the account below rent-exemption unless it leaves it empty.

Both instructions take only `[vector_pda, receiver]` as accounts and gate on `vector.is_signer()`. They are not directly callable: the user authorises them by embedding the close/withdraw sub-instruction in a `Passthrough` instruction and signing an `Advance` whose digest commits to it. Advance verifies the offchain signature and advances the nonce; the sibling Passthrough then re-enters this program with the PDA promoted to signer — that re-entry is what trips the gate.

Because the signed digest commits to the entire transaction, the recipient and surrounding instructions are bound to the signature: a relayer cannot redirect the lamports or splice in extra top-level instructions without invalidating it.

## Client SDKs

### Rust (`vector-core`)

The `vector-core` crate provides off-chain helpers for constructing Vector transactions. It depends on the program crate itself, so the program ID, the account header, the discriminators and every scheme's byte and lengths come from the program and cannot drift. It exposes `PROGRAM_ID` and the program's `Scheme` descriptor (`id`, `identity_len`, `stored_identity_len`, `signature_len`, `next_key_len`) with the constants `ED25519`, `EIP191`, `FALCON512`, `MLDSA44`, `SECP256K1`, `WINTERNITZ`, `XMSS`:

- `find_vector_pda(&scheme, identity)` — derive the canonical Vector PDA (`["vector", [scheme], sha256(identity)]`).
- `create_initialize_ed25519(payer, pubkey)` / `create_initialize_secp256k1_eip191(payer, eth_addr)` / `create_initialize_secp256k1_ecdsa(payer, compressed_pubkey)` / `create_initialize_falcon512(payer, wire_pubkey)` / `create_initialize_mldsa44(payer, public_key)` — convenience wrappers; ML-DSA-44's returns its three instructions.
- `create_initialize_instruction(payer, &scheme, identity)` — generic init-instruction builder; `create_initialize_instructions` returns every call the scheme needs.
- `find_system_pda(&vector)` — the account's system PDA.
- `create_close_subinstruction(&scheme, identity, close_to)` / `create_withdraw_subinstruction(&scheme, identity, receiver, lamports)` — sub-instruction builders for embedding inside a `passthrough` payload.
- `create_advance_instruction(&scheme, identity, signature)` — assemble an advance instruction (signature only, no embedded payload) from a precomputed signature. `create_multi_advance_instruction(&[(AdvanceSigner::new(&scheme, identity), signature)])` does the same for several signers. For Winternitz and XMSS use `create_rotating_advance_instruction(&scheme, identity, next_key, signature)`.
- `create_passthrough_instruction(&scheme, identity, sub_ixs)` — assemble the passthrough instruction that replays `sub_ixs` under the PDA's signer seeds; include it among the pre/post instructions so the digest commits to it. `create_system_passthrough_instruction` signs as the system PDA; `create_multi_passthrough_instruction(&[PassthroughSigner::vector(&scheme, identity), PassthroughSigner::system(..)], sub_ixs)` signs for several.
- `advance_vector_digest(&scheme, nonce, identity, pre, post, fee_payer)` — recompute the SHA-256 digest the on-chain program will verify. For Winternitz and XMSS use `rotating_advance_vector_digest`. With several signers, compute `advance_message(&[AdvanceSigner::new(&scheme, identity)], pre, post, fee_payer)` once, then `signer_digest(&message, nonce, &vector, next_key)` for each.
- `sign_advance_instruction_ed25519(signing_key, nonce, pre, post, fee_payer)` — sign with Ed25519.
- `sign_advance_instruction_secp256k1_eip191(signing_key, nonce, pre, post, fee_payer)` — sign with EIP-191 (envelope, 65-byte sig).
- `sign_advance_instruction_secp256k1_ecdsa(signing_key, nonce, pre, post, fee_payer)` — sign with plain secp256k1 ECDSA (64-byte sig).
- `signed_nonce(&nonce, &vector_nonce)` / `create_initialize_nonce_instruction(&nonce_account, &vector)` / `create_close_nonce_subinstruction(&scheme, identity, &nonce_account, &close_to)` / `NonceAccount::LEN` — nonce accounts.
- `verify_advance_signature(AdvanceSigner::new(&scheme, identity), nonce, pre, post, fee_payer, signature)` — verify an advance signature fully offline with the program's own code, for every scheme but Winternitz and XMSS; returns the digest (= next nonce) on success. See [Offline verification](#offline-verification).
- `ed25519_pubkey` / `secp256k1_eip191_eth_address` / `secp256k1_compressed_pubkey` / `eth_address_from_pubkey` / `eip191_envelope_hash(digest)` — identity/envelope utilities.

Falcon-512 and ML-DSA-44 signing are intentionally left to the caller (`solana-falcon512` and `solana-ml-dsa` are verify-only) — pair with an external signer such as `pqcrypto-falcon` or `fips204` (empty context) and feed the wire-format signature into `create_advance_instruction`.

### TypeScript (`vector-sdk`)

The TypeScript SDK mirrors the Rust SDK and exposes the same `Scheme` objects (`ED25519`, `EIP191`, `FALCON512`, `MLDSA44`, `SECP256K1`, `WINTERNITZ`, `XMSS`):

- `findVectorPda(scheme, identity)` — derive the canonical Vector PDA.
- `fetchVectorAccount(connection, scheme, identity)` — fetch and deserialize the 68-byte header.
- `createInitializeEd25519(payer, pubkey)` / `createInitializeEip191(payer, ethAddress)` / `createInitializeSecp256k1(payer, compressedPubkey)` / `createInitializeFalcon512(payer, wirePubkey)` / `createInitializeMlDsa44(payer, publicKey)` — convenience wrappers; ML-DSA-44's returns its three instructions.
- `createInitializeInstruction(payer, scheme, identity)` — generic init builder; `createInitializeInstructions` returns every call the scheme needs.
- `findSystemPda(vector)` — the account's system PDA.
- `createCloseSubinstruction(scheme, identity, closeTo)` / `createWithdrawSubinstruction(scheme, identity, receiver, lamports)` — sub-instruction builders.
- `createAdvanceInstruction(scheme, identity, signature)` — assemble from precomputed signature (signature only, no embedded payload). `createMultiAdvanceInstruction([{ scheme, identity, nonceAccount?, nextKey?, signature }])` does the same for several signers. For Winternitz and XMSS use `createRotatingAdvanceInstruction(scheme, identity, nextKey, signature)`.
- `createPassthroughInstruction(scheme, identity, subIxs)` — assemble the passthrough instruction that replays `subIxs` under the PDA's signer seeds; include it among the pre/post instructions so the digest commits to it. `createSystemPassthroughInstruction` signs as the system PDA; `createMultiPassthroughInstruction([{ scheme, identity, system? }], subIxs)` signs for several.
- `advanceVectorDigest(scheme, nonce, identity, pre, post, feePayer?)` — recompute the digest. For Winternitz and XMSS use `rotatingAdvanceVectorDigest`. With several signers, `advanceMessage([{ scheme, identity, nextKey? }], pre, post, feePayer?)` once, then `signerDigest(message, nonce, vector, nextKey?)` for each.
- `signAdvanceInstructionEd25519(signingKey, nonce, pre, post, feePayer?)` — sign with Ed25519.
- `signAdvanceInstructionEip191(privateKey, nonce, pre, post, feePayer?)` — sign with EIP-191 secp256k1.
- `signAdvanceInstructionSecp256k1(privateKey, nonce, pre, post, feePayer?)` — sign with plain secp256k1 ECDSA.
- `signAdvanceInstructionFalcon512(keypair, nonce, pre, post, feePayer?)` — sign with Falcon-512 (post-quantum) via [`@noble/post-quantum/falcon.js`](https://github.com/paulmillr/noble-post-quantum); plus `falcon512Keygen`, `falcon512PublicKey`.
- `signAdvanceInstructionMlDsa44(keypair, nonce, pre, post, feePayer?)` — sign with ML-DSA-44 (FIPS 204, post-quantum) via `@noble/post-quantum/ml-dsa.js`, empty context; plus `mldsa44Keygen`, `mldsa44PublicKey`.
- `signedNonce(nonce, vectorNonce)` / `createInitializeNonceInstruction(nonceAccount, vector)` / `createCloseSubinstruction(scheme, identity, closeTo, nonceAccount?)` / `NONCE_ACCOUNT_LEN` / `NonceAccount.fromAccountData(data)` / `fetchNonceAccount(connection, nonceAccount)` — nonce accounts; `createNonceAccount`, `getNonce`, `closeNonceAccount`, `systemAccount` and `NoncedTransaction` take web3.js durable nonce shapes (see [Migrating](#migrating-from-durable-nonces-blueshift-nonce)).
- `verifyAdvanceSignature({ scheme, identity, nonceAccount? }, nonce, pre, post, signature, feePayer?)` — verify an advance signature fully offline, for every scheme but Winternitz and XMSS; returns the digest (= next nonce) or throws a named error. Plus `normalizeEip191RecoveryByte(v)` for converting Ethereum tooling's legacy 27/28 recovery byte at assembly time.
- `ed25519Identity` / `eip191Identity` / `secp256k1Identity` / `eip191EnvelopeHash(digest)` — identity/envelope utilities.

The TypeScript SDK implements signing for Ed25519, EIP-191, Secp256k1, Falcon-512 and ML-DSA-44. Winternitz and XMSS signing are supplied by the caller. Falcon-512 uses `@noble/post-quantum`'s compressed detached signature zero-padded to the 666-byte wire format `solana-falcon512` reads. The plain Secp256k1 scheme uses [`@noble/curves/secp256k1`](https://github.com/paulmillr/noble-curves) `secp256k1.sign(...).toCompactRawBytes()` for the 64-byte `(r, s)` wire form.

Each scheme is its own importable entrypoint (the npm feature-flag analogue) so a consumer only pulls the crypto it uses: `import { signAdvanceInstructionFalcon512 } from "vector-sdk/falcon512"` (Falcon + PQ lib only), `"vector-sdk/mldsa44"` likewise vs `import { ... } from "vector-sdk"` (everything).

The signed digest doubles as the next on-chain nonce, so a successful advance always replaces `nonce` with the digest that authorized it.

## Operational Patterns

Everything below is native protocol behaviour — no extra programs or formats. The building blocks are the digest (`SHA256(message || nonce || vector_address || next_key)`), digest-as-next-nonce progression, and the fact that each nonce, a vector's own or a nonce account's, has exactly one outstanding value.

### Offline verification

Both SDKs ship a verify function that recomputes the digest from the full instruction layout and checks the signature as the on-chain program will — no RPC. The Rust one runs the program's own `initialize` and `advance` for the scheme, with `sol_secp256k1_recover` as the runtime implements it, so it cannot disagree with the chain. The TypeScript one verifies with `@noble`, and shares its digest pins and `fixtures/program.json` with the Rust tests. A PASS means the transaction will verify on-chain against the same nonce; the returned digest is the account's next nonce.

```rust
use vector_core::{verify_advance_signature, AdvanceSigner, ED25519};

let next_nonce = verify_advance_signature(
    AdvanceSigner::new(&ED25519, &pubkey), &nonce, &pre_ixs, &post_ixs, None, signature,
)?;
```

The fee payer affects the digest only when its key appears in a committed instruction: message-level flag promotion then folds it in as a writable signer.

### Nonce accounts

A vector account holds one nonce, so the transactions signed over it run one at a time. For more in flight at once, give the vector nonce accounts: each is a nonce of its own, and a chain of its own, while the vector account still signs, holds the funds and is the authority. It is the System program's durable nonce flow: one authority, many nonce accounts.

- **Create.** As with the System program: a System `CreateAccount` of `NONCE_ACCOUNT_LEN` bytes assigned to Vector, then `InitializeNonce`, both signed by the new account's keypair, so no one can initialize it in between. Anyone can pay for one, for any vector: only the vector's key can advance or close it. Its first nonce is `SHA256("nonce" || address || latest slot hash)`, as a vector's takes in the slot hash. `InitializeNonce` costs 727 CUs.
- **Sign over one.** List it right after its vector in the `Advance` (`AdvanceSigner { nonce_account: Some(address), .. }` / `{ nonceAccount }`). The signer signs over `SHA256(nonce account's nonce || vector's own nonce)` (`signed_nonce` / `signedNonce`) in place of a nonce; the digest is otherwise unchanged. The message covers the account list, so a signature over one nonce account cannot be moved to another. Landing it moves that account's nonce only.
- **In any order.** Transactions over different nonce accounts land, fail and retry independently. Over one nonce account they stay ordered, with the same chain and pre-signing as the vector's own nonce, while the vector's own nonce stays put.
- **Cancel everything.** Move the vector's own nonce: one `Advance` entry, with nothing else in its transaction. Every signature outstanding over the vector or any of its nonce accounts dies, since each took in that nonce. The nonce accounts themselves do not move; sign over their new `signed_nonce`.
- **Not in its creation slot.** `Advance` and `Close` refuse a nonce account in the slot it was created in (`FreshNonce`). So an account closed and created again starts from a slot hash it never had, and never holds a nonce it held before.
- **Close.** `Close` inside a `Passthrough`, with the nonce account as a third account, sends its lamports to the receiver and removes it. `close_nonce_account` / `closeNonceAccount` build it.
- **Not for Winternitz or XMSS.** Two nonces in flight would be two signatures by one key, so `InitializeNonce` refuses those vectors (`KeyRotates`).

### Migrating from durable nonces (`blueshift-nonce`)

`crates/nonce` is the `blueshift-nonce` crate: a library with the shapes durable nonce code already uses, and a CLI with the `solana` CLI's nonce commands. The cold key stays the nonce authority and signs offline with any `solana_signer::Signer`, a `Keypair` included.

The one move: the authority's SOL, token accounts, and mint, freeze and stake authorities go once to `system_account(authority)` (`blueshift-nonce address`), a System account like any wallet. Instructions keep naming the cold key; `NoncedMessage` puts `system_account` in its place, and Vector signs as it.

| Durable nonce | `blueshift-nonce` |
|---|---|
| `create_nonce_account(from, nonce, authority, lamports)` | the same |
| `Message::new_with_nonce(ixs, payer, nonce, authority)` | `NoncedMessage::new_with_nonce(ixs, payer, nonce, authority)` |
| `Transaction::new_unsigned(message)` | `NoncedTransaction::new_unsigned(message)` |
| `tx.try_partial_sign(&[&authority], nonce)`, offline | the same |
| `bincode::serialize(&tx)`, to carry it | the same: it serializes as a plain `Transaction` |
| `tx.try_partial_sign(&[&payer, ..], nonce)`, then send | `tx.try_partial_sign(&[&payer, ..], recent_blockhash)` on that `Transaction`, then send |
| `advance_nonce_account` (cancel) | `NoncedMessage::new_with_nonce(vec![], ..)` |
| `withdraw_nonce_account` | `close_nonce_account(nonce, authority, to)`, for all its lamports, in a `NoncedMessage` |
| `solana_nonce::state::{State, Data}`, `state_from_account`, `data_from_account`, `data_from_state`, `account_identity_ok` | the same names; `state_from_account` / `data_from_account` also take the vector account, whose nonce is part of `Data::blockhash()`. Fetch both with your own RPC client |
| `solana create-nonce-account KEYPAIR AMOUNT --nonce-authority PUBKEY` | `blueshift-nonce create-nonce-account ..`, which also creates the authority's vector |
| `solana nonce` / `new-nonce` / `withdraw-from-nonce-account` | `blueshift-nonce nonce` (also `nonce-account`) / `new-nonce` / `close-nonce-account` |
| `solana transfer TO AMOUNT --nonce N --nonce-authority KEY --sign-only` | `blueshift-nonce transfer TO AMOUNT --nonce N --nonce-authority KEY --sign-only`, from `system_account`; `--blockhash NONCE` signs with no RPC |
| `--signer AUTHORITY=SIG`: submit later | the same |

Whoever submits handles a plain `Transaction` and needs nothing from this crate: the nonce authority's signature travels inside Vector's `Advance`, and the fee payer and any other signer, such as a new account, sign the transaction over a recent blockhash.

TypeScript, on `@solana/web3.js`, takes the same shapes:

| `@solana/web3.js` durable nonce | Vector SDK |
|---|---|
| `SystemProgram.createNonceAccount({ fromPubkey, noncePubkey, authorizedPubkey, lamports })` | `createNonceAccount({ .. })`, the same parameters |
| `connection.getNonce(nonceAccount).nonce` | `getNonce(connection, nonceAccount)`, as bytes |
| `SystemProgram.nonceWithdraw(..)` | `closeNonceAccount({ noncePubkey, authorizedPubkey, toPubkey })`, for all its lamports |
| `new Transaction({ feePayer, nonceInfo: { nonce, nonceInstruction } })` | `new NoncedTransaction({ feePayer, nonceInfo: { nonce, nonceAccount, authority } })` |
| `tx.add(SystemProgram.transfer({ fromPubkey: authority, .. }))` | the same; the authority becomes `systemAccount(authority)` |
| `await tx.partialSign(authority)`, `tx.serialize({ requireAllSignatures: false })` | the same |
| `Transaction.from(bytes)`, `partialSign(feePayer)`, send | the same, after `tx.recentBlockhash = latest` |

The library needs no RPC client; the CLI is its default `cli` feature (`default-features = false` leaves it out). The CLI reads `solana config` for the URL and the fee payer (`--fee-payer` takes a pubkey with `--sign-only`). Its signers are keypair files for now, not `usb://` or `prompt:`.

What else changes: whoever submits sets a recent blockhash, while the authority's signature stays valid until its nonce moves. `authorize_nonce_account` has no counterpart: a nonce account belongs to one vector. `BlockhashQuery` is left out, because the nonce and the blockhash are now separate values.

### Unilateral revocation

An `advance` with empty pre/post instructions is an inert transition: it verifies, installs the next nonce, and does nothing else. Signed at the outstanding nonce, it is a kill-switch — landing it orphans every signature derived from that nonce (see [Invalidation and Forward Exposure](#invalidation-and-forward-exposure)). Pre-sign the inert advance in the same session as the transactions it guards; broadcasting it later requires no further access to the key.

Both SDKs ship this as sugar over the advance signers: `sign_revocation_instruction_ed25519(key, nonce)` / `_secp256k1_ecdsa` / `_secp256k1_eip191` (Rust), `signRevocationInstructionEd25519(key, nonce)` / `Secp256k1` / `Eip191` (TypeScript), plus `revocation_digest(scheme, nonce, identity)` / `revocationDigest(...)` to recompute what they commit to. Verifying one is just the ordinary advance verifier with empty pre/post. The digest commits to the broadcasting transaction's instructions sysvar, so the revocation must be broadcast as a transaction containing **only** the advance instruction — adding so much as a compute-budget ix afterwards invalidates the signature. The three covered schemes fit the default compute budget (~13k/26k/72k CUs); Falcon-512 has no zero-arg sugar by design — sign via the advance signer with a compute-budget pre-instruction committed at sign time, since its ~184k CU inert advance leaves no headroom under the 200k default.

### Ordered pre-signing

The digest returned at sign time **is** the nonce after that advance lands, so a chain of dependent transactions can be pre-signed in one session: sign transaction 1 against the current nonce, transaction 2 against transaction 1's digest, and so on. The chain can only execute in order — transaction 2 cannot become valid until transaction 1 has landed — and an inert advance signed at any link's nonce severs the chain from that point.

### Expiry

A timeout instruction placed inside the signed buffer is committed to by the digest like everything else (see [Transaction Expiration](#transaction-expiration)). Pair pre-signed transactions with a deadline instruction such as [sbpf-asm-timeout](https://github.com/deanmlittle/sbpf-asm-timeout) so a withheld transaction dies on its own instead of waiting for a kill-switch.

## License
MIT
