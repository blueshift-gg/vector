# Vector
Vector is a Solana primitive for offchain transaction signing that can be used in place of durable nonce workflows.

It works by computing a SHA-256 digest of a transaction offchain, signing that digest with one of several supported schemes, and then reproducing the same digest onchain from the instructions sysvar at execution time. The on-chain program verifies the signature before allowing execution to proceed.

This means a Vector account can be controlled by a standard Solana Ed25519 keypair, a plain secp256k1 ECDSA key, an Ethereum (EIP-191) secp256k1 address, or a post-quantum Falcon-512, Winternitz or XMSS key. Each scheme ships as its **own program** with its own program ID; all of them share the account header and authorization flow. Winternitz and XMSS additionally support key rotation and require persistent signing state.

## Execution Model
A Vector authorization flow proceeds as follows:

1. A transaction is constructed offchain.
2. The signature field is replaced with the current Vector nonce and account public key.
3. The resulting instruction buffer is SHA-256 hashed and the digest is signed offchain.
4. The transaction is submitted onchain.
5. Vector reads the instruction sysvar, performs the same substitution, recomputes the SHA-256 digest, and verifies the signature against it.

If verification succeeds, Vector installs that same digest as its next nonce, creating a history-based hashchain. Any CPIs the signer authorized run in a sibling top-level `Passthrough` instruction in the same transaction (see [Passthrough CPI](#passthrough-cpi)); the digest commits to its exact bytes.

Pre-hashing with SHA-256 keeps the input handed to the on-chain verifier constant-sized regardless of how large the hosting transaction is, which dramatically reduces the work performed inside signature verification.

The fee payer or relayer is therefore not entrusted with authority over transaction contents at any time, as they are unable to alter the authorized transaction buffer without invalidating its corresponding signature.

## Multi-Scheme Support

Vector ships one program per signing scheme. The instruction set, account header, nonce progression and CPI passthrough are implemented in the [`vector-common`](crates/common/) crate; each program is a thin shell that plugs in one `SigningScheme` impl and routes discriminators to the shared handlers via `vector_common::dispatch::<Scheme>`. Adding a scheme is a new program crate (a `declare_id!`, a `SigningScheme` impl, and a one-line dispatch). Winternitz and XMSS use `vector_common::rotating::dispatch`, which adds a fixed account identity and key rotation around the shared handlers.

| Scheme | Program ID | Identity | Signature | On-Chain Identity Storage | Pre-Sign Wrapper |
|--------|------------|----------|-----------|---------------------------|------------------|
| Ed25519    | `vectorcLBXJ2TuoKuUygkEi6FWqvBnbHDEDWoYamfjV` | 32-byte public key                | 64 bytes `(r, s)`    | 32 B pubkey                          | SHA-256          |
| Secp256k1  | `9NCknbW4LpePSZzbZGFk2HHsSH4y4pkmRjEguJo7qqjd` | 33-byte compressed pubkey         | 64 bytes `(r, s)`    | 33 B compressed pubkey               | SHA-256          |
| EIP-191    | `G6okL1MvXx7k5eytY7wRXNupXyYG1QVZW37ygAjMiTTu` | 20-byte ETH address               | 65 bytes `(r, s, v)` | 20 B ETH address                     | EIP-191 + SHA-256|
| Falcon-512 | `HdkE3dPYgCRZJgLv64mbFmojyCprUim8VRXzK2wR6Qgm` | `sha256(wire_pubkey_897)`         | 666 bytes (zero-padded compressed) | 32 B hash + 1 B pad + 1024 B prepared pubkey | SHA-256 |
| Winternitz | `GvCGfvMTr8YZJZkV9KxaGF1Y2EzxUksur8iDwjVwJwGf` (local) | `sha256(initial_pubkey)` | 849 bytes | 32 B identity + 41 B current key | SHA-256 |
| XMSS | `7qCyy3NJQDMctSDiM4DxNjNR6TyasouyyRTBREhcXdsE` (local) | `sha256(initial_pubkey)` | 1,037 bytes | 32 B identity + 41 B current key | SHA-256 |

Because the program ID identifies the scheme, there is no on-chain scheme discriminator: no `key_type` byte in the account, and no `key_type` in the PDA seeds. The previous BSM and Schnorr schemes have been removed.

### Ed25519
The signer's 32-byte Ed25519 public key is stored directly in the account. The 64-byte `(r, s)` signature is verified directly over the SHA-256 digest. Verification uses [`brine-ed25519`](https://github.com/zfedoran/brine-ed25519) with its `fast-sha512` feature, which keeps Ed25519 advance under ~14k CUs.

### Secp256k1 (plain ECDSA)
A standard secp256k1 ECDSA signer with sec1-compressed public keys. The 33-byte compressed pubkey (`0x02`/`0x03` prefix + 32-byte x-coordinate) is the identity: stored verbatim after the account header and used directly (`> 32` bytes → `sha256`) as the PDA seed. Signatures are 64 bytes `(r, s)` with no recovery byte; verification runs standard ECDSA via the [`solana-secp256k1-ecdsa`](https://crates.io/crates/solana-secp256k1-ecdsa) crate (~72k CUs advance).

This scheme is the natural fit for non-EIP-191 secp256k1 contexts (Bitcoin-style apps, generic crypto libraries) and pairs with anything producing standard ECDSA signatures.

### EIP-191 (Ethereum)
The signer's 20-byte Ethereum address is the identity, stored raw (no padding) after the account header and used directly as the PDA seed.

Signatures are 65 bytes: `r(32) || s(32) || v(1)`, where `v` is the ECDSA recovery ID (0 or 1). Embedding `v` in the instruction data allows on-chain verification with a single `sol_secp256k1_recover` call. The recovery ID is inside the signature carve-out, so it is excluded from the digest and does not create a circular dependency.

Before signing and recovery, the SHA-256 digest is wrapped in an EIP-191 personal-sign envelope:

```
signed_hash = keccak256("\x19Ethereum Signed Message:\n32" || digest)
```

This means any standard Ethereum wallet that supports `personal_sign` can produce valid Vector signatures. On-chain, the program applies the same EIP-191 wrapping before calling `secp256k1_recover`, then derives the Ethereum address via `keccak256(recovered_pubkey)[12..32]` and compares it against the stored address.

### Falcon-512
Vector supports the post-quantum [Falcon-512](https://falcon-sign.info/) lattice signature scheme via [`solana-falcon512`](https://github.com/blueshift-gg/solana-falcon512), giving forward-secure account control even against an adversary with a cryptographically relevant quantum computer.

Wire pubkeys are 897 bytes. The client identity — the PDA seed and the value folded into the advance digest — is `sha256(wire_pubkey)` (32 bytes), which a client computes from its wire pubkey with plain SHA-256 (no preparation step). Anyone deriving the PDA off-chain therefore needs the full wire pubkey, not just its hash.

To keep on-chain verification cheap, Vector stores Falcon's *prepared pubkey* (a 1024-byte form with the forward NTT and modular inverse pre-baked) in the account's identity region. The stored identity is `sha256(wire_pubkey)[32] || pad[1] || prepared_pubkey[1024]`; the one-byte pad lands the prepared form on a 2-byte account offset so the verifier can borrow it zero-copy (a 1024-byte stack copy would overflow the BPF frame). The prepared form is computed once at `initialize` (~63k CUs); subsequent `advance` calls only pay the signature-verify cost (~184k CUs). The 32-byte hash prefix is what `advance` folds into the digest, since the client can't reproduce the prepared form and the program can't cheaply rebuild the wire pubkey.

Falcon signatures are variable-length (compressed Huffman); the wire format zero-pads to 666 bytes so the digest carve-out is constant-sized.

### Winternitz and XMSS

Both programs link [`solana-winternitz`](https://github.com/blueshift-gg/solana-winternitz): DKKW25 target-sum Winternitz and generalized XMSS with Keccak-256. The one-time instance has an 849-byte signature; the height-8 XMSS instance has a 1,037-byte signature and 256 leaves. Both public keys are 41 bytes. This XMSS variant is not compatible with RFC 8391.

The account is 106 bytes:

```text
nonce[32] || bump[1] || identity[32] || current_public_key[41]
```

`identity = sha256(initial_public_key)` is permanent. It is the PDA seed and the identity folded into the Vector digest. Verification uses `current_public_key`, which can change without moving the account or its assets and authorities. This separation also appears in [Winterwallet's account layout](https://github.com/blueshift-gg/winterwallet/blob/672fc6789b1532ee680f24842d235e0be8737b61/program/src/state.rs).

Both SDKs expose `WINTERNITZ` / `XMSS`, initialization helpers and `winternitz_identity` / `xmss_identity` (`winternitzIdentity` / `xmssIdentity` in TypeScript). Derive the identity from the first key and keep using it for every instruction and digest after rotation. Signing belongs to the caller's persistent signer; the Vector SDKs do not implement signing for these schemes.

### Key rotation

Generate and persist a fresh signer, then authorize its public key with the current signer:

```text
Advance(current-key signature)
Passthrough([Rotate(next_public_key), ...actions])
```

`create_rotate_subinstruction` / `createRotateSubinstruction` builds the `Rotate` payload. The existing Vector digest commits to the replacement key and all actions. Rotation changes only the stored public key; the PDA seed and bump remain fixed. The nonce advances through the ordinary `Advance` handler. Direct, unsigned rotation and replacing a key with itself are rejected. Rotation stays within the account's signing scheme.

For Winternitz, every authorization must rotate to a fresh key or close the account. This is a signing requirement, not an on-chain history of used keys: callers must never reinstall a used key or sign two different authorizations with one key. XMSS can authorize multiple transactions under one tree; reserve a leaf for rotation before exhaustion. Failed salt sampling and abandoned authorizations consume signing attempts too.

Rotation and actions are atomic. If any instruction fails, the nonce and key changes roll back. Retain the signed authorization and rebroadcast it unchanged when the cause is resolved. A permanently failing action cannot be repaired by changing the transaction and reusing a Winternitz key; this integration has no separate recovery authorization. The Vector nonce prevents replay of successful transactions, but cannot prevent off-chain leaf reuse.

The workspace currently uses the adjacent `../solana-winternitz` checkout. Publish that crate and replace the path dependency before release. Build each program with `cargo build-sbf --manifest-path programs/xmss/Cargo.toml`, substituting `winternitz` for the one-time program. The listed program IDs are local and undeployed.

### Digest Construction
All schemes share the same SHA-256 digest over the instructions sysvar buffer. The signature region is carved out of the buffer and replaced with the current nonce and the scheme's identity:

```
digest = SHA256(buffer[..sig_start] || nonce || identity || buffer[sig_end..])
```

`identity` is the client-derivable identity: the stored pubkey/address for Ed25519/EIP-191/Secp256k1, `sha256(wire_pubkey)` for Falcon-512, and the permanent `sha256(initial_pubkey)` for Winternitz/XMSS (the program's `digest_identity` hook selects it). The carve-out size is the signature length listed for each scheme above. Everything else in the buffer — the discriminator, CPI payload, surrounding instructions, and sysvar framing — is committed to by the digest.

## Instruction Set
Every Vector program exposes instructions 0–4. Winternitz and XMSS also expose `Rotate` (5). Each instruction starts with its discriminator byte.

| Disc | Name        | Top-Level Callable? | Authorisation                                |
|------|-------------|---------------------|----------------------------------------------|
| `0`  | Initialize  | yes | payer funds creation |
| `1`  | Advance     | **only** top-level (CPI guarded) | offchain signature over the canonical digest |
| `2`  | Close       | only via Passthrough reentry | inherited from the authorising Advance       |
| `3`  | Withdraw    | only via Passthrough reentry | inherited from the authorising Advance       |
| `4`  | Passthrough | **only** top-level (CPI guarded) | a sibling Advance for the same vector PDA earlier in the same transaction |
| `5`  | Rotate | only via Passthrough reentry | current-key authorization; Winternitz/XMSS only |

`Advance` carries only the signature — its handler verifies it, installs the digest as the next nonce, and rejects any trailing payload. CPIs under the PDA's signer seeds go in a separate top-level `Passthrough` instruction, whose handler scans the instructions sysvar and refuses to run unless a prior `Advance` for the same vector PDA appears earlier in the transaction. `Close` and `Withdraw` are reachable as top-level instructions in name only — their handlers gate on `vector.is_signer()`, which can only be true when the instruction is reached as a CPI from `Passthrough` (which signs as the PDA via `invoke_signed`). The user authorises any combination of close/withdraw/arbitrary CPIs by signing an `Advance` whose digest commits to the sibling `Passthrough`'s exact bytes. Winterwallet combines key advancement and CPIs in one instruction; Vector keeps `Advance` and `Passthrough` separate.

## Passthrough CPI
Vector acts as a narrow CPI gate in front of ordinary Solana execution. Its role is limited to verifying that the current transaction exactly matches the transaction that was signed offchain against the current Vector state. Once `Advance`'s check succeeds, a sibling top-level `Passthrough` instruction in the same transaction replays its embedded sub-instructions, taking its trailing accounts along with the embedded instruction data and performing CPI actions for the owner. The passthrough handler authorises itself by scanning the instructions sysvar for a prior `Advance` against the same vector PDA — transaction atomicity guarantees that advance verified, or the whole transaction aborted.

After Passthrough CPI, the downstream instruction flow proceeds as normal. As Vector does not alter downstream semantics, it composes naturally with all existing Solana instruction patterns, including those that depend on temporary authority transfer or intra-transaction liquidity, such as flash loans.

Although `passthrough` only replays its own embedded sub-instructions, the digest `advance` verifies covers every top-level instruction in the hosting transaction — including the passthrough's data and account layout. Pre- and post-instructions placed alongside `advance` are committed to by the same signature even though Vector never executes them itself. This is what lets a compute-budget instruction, balance check, or memo coexist with a Vector-authorized payload without weakening the signer's authority — provided they are part of the buffer at signing time; a relayer cannot add them afterwards without invalidating the signature.

For each sub-instruction in the passthrough payload, Vector promotes any account whose address matches the vector PDA to `is_signer = true` before invoking. This is what lets `Close`/`Withdraw` pass their `vector.is_signer()` gate when reached via re-entry, and lets arbitrary downstream programs treat the PDA as the signer for authority operations (e.g. SPL Token `set_authority`).

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
next_nonce = SHA256(pre || current_nonce || identity || post)
```

where `pre` and `post` together cover the entire instructions sysvar buffer minus the signature region. Because `current_nonce` is itself an input to the hash, every nonce transition is a deterministic function of both the prior state and the exact transaction being authorized — there is no separate mixing pass and no second hash.

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

A Vector account is a PDA at `["vector", identity_seed]` under the scheme's program, with a fixed 33-byte header followed by the scheme's identity bytes:

```
nonce:    [u8; 32]  // offset  0 — current state nonce
bump:     u8        // offset 32 — PDA bump seed
identity: [u8; N]   // offset 33 — N = stored identity length
```

`identity_seed` is derived from the client identity: the identity itself when it is `<= 32` bytes, otherwise `sha256(identity)`. For Winternitz/XMSS it is the fixed 32-byte hash of the initial key, even after rotation.

| Scheme      | Total Account Size | Identity Bytes (offset 33)                      |
|-------------|--------------------|-------------------------------------------------|
| Ed25519     | 65 B               | 32 B public key                                 |
| EIP-191     | 53 B               | 20 B ETH address                                |
| Secp256k1   | 66 B               | 33 B compressed pubkey                          |
| Falcon-512  | 1090 B             | 32 B `sha256(wire)` + 1 B pad + 1024 B prepared |
| Winternitz / XMSS | 106 B | 32 B permanent identity + 41 B current public key |

Because each scheme is its own program, the program ID is the scheme discriminator — there is no `key_type` byte and no `key_type` PDA seed. Cross-scheme collision is impossible: two schemes cannot share a PDA because the PDA is derived under a different program ID.

## Initialization
A Vector account is created via the `initialize` instruction, which allocates the `33 + stored_identity_len` byte PDA under the scheme's program. Instruction data: `[disc, ...init_payload]` (no scheme byte — the program identifies the scheme), where `init_payload` is scheme-defined:

| Scheme      | `init_payload`            | Stored Identity                              |
|-------------|---------------------------|----------------------------------------------|
| Ed25519     | 32-byte pubkey            | the pubkey verbatim                          |
| EIP-191     | 20-byte ETH address       | the address verbatim                        |
| Falcon-512  | 897-byte wire pubkey      | `sha256(wire)[32] \|\| pad[1] \|\| prepared[1024]` |
| Secp256k1   | 33-byte compressed pubkey | the compressed pubkey verbatim              |
| Winternitz / XMSS | 41-byte public key | `sha256(initial_pubkey)[32]` followed by the current 41-byte key |

`initialize` allocates the full `33 + stored_identity_len` bytes in a single
`CreateAccount` CPI; every scheme registers in one call.

For Ed25519, the pubkey must be a valid curve point. For EIP-191, the 20-byte address must be non-zero. For Secp256k1, the compressed pubkey must start with `0x02` or `0x03`. For Falcon-512, the wire pubkey is validated and expanded into the 1024-byte prepared form at init time.

The initial nonce is derived entirely onchain using the `sol_get_sysvar` syscall to read the most recent slot hash and height from the `SlotHashes` sysvar: `sha256(identity_seed || latest_slot_entry)`. This time-based pRNG mechanism ensures that if an account is closed and the same identity is later re-initialized, the nonce will differ, as the slot hash changes in every slot. The conditions required to replay a prior signature chain would require the account to be: opened, used, closed, reopened, and replayed all within the same slot; a set of circumstances that is technically infeasible without cooperation of both the private key holder and a colluding validator.

## Closing and Partial Withdraw
`Close` empties the PDA's lamports into a `close_to` account; once balance hits zero the runtime reclaims the PDA at the instruction boundary. `Withdraw` moves a fixed amount of lamports out while preserving the rent-minimum balance so the account survives.

Both instructions take only `[vector_pda, receiver]` as accounts and gate on `vector.is_signer()`. They are not directly callable: the user authorises them by embedding the close/withdraw sub-instruction in a `Passthrough` instruction and signing an `Advance` whose digest commits to it. Advance verifies the offchain signature and advances the nonce; the sibling Passthrough then re-enters this program with the PDA promoted to signer — that re-entry is what trips the gate.

Because the signed digest commits to the entire transaction, the recipient and surrounding instructions are bound to the signature: a relayer cannot redirect the lamports or splice in extra top-level instructions without invalidating it.

## Client SDKs

### Rust (`vector-core`)

The `vector-core` crate provides off-chain helpers for constructing Vector transactions. It exposes a `Scheme` descriptor (`program_id`, `signature_len`, `identity_len`, `stored_identity_len`) with the constants `ED25519`, `EIP191`, `FALCON512`, `SECP256K1`, `WINTERNITZ`, `XMSS`:

- `create_rotate_subinstruction(&scheme, &identity, new_public_key)` — authorize a Winternitz/XMSS key replacement through Passthrough.
- `find_vector_pda(&scheme, identity)` — derive the canonical Vector PDA (`["vector", identity_seed]`).
- `create_initialize_ed25519(payer, pubkey)` / `create_initialize_secp256k1_eip191(payer, eth_addr)` / `create_initialize_secp256k1_ecdsa(payer, compressed_pubkey)` / `create_initialize_falcon512(payer, wire_pubkey)` — convenience wrappers.
- `create_initialize_instruction(payer, &scheme, identity, init_payload)` — generic init-instruction builder.
- `create_close_subinstruction(&scheme, identity, close_to)` / `create_withdraw_subinstruction(&scheme, identity, receiver, lamports)` — sub-instruction builders for embedding inside a `passthrough` payload.
- `create_advance_instruction(&scheme, identity, signature)` — assemble an advance instruction (signature only, no embedded payload) from a precomputed signature.
- `create_passthrough_instruction(&scheme, identity, sub_ixs)` — assemble the passthrough instruction that replays `sub_ixs` under the PDA's signer seeds; include it among the pre/post instructions so the digest commits to it.
- `advance_vector_digest(&scheme, nonce, identity, pre, post)` / `advance_vector_digest_with_fee_payer(&scheme, nonce, identity, pre, post, fee_payer)` — recompute the SHA-256 digest the on-chain program will verify.
- `sign_advance_instruction_ed25519(signing_key, nonce, pre, post)` — sign with Ed25519.
- `sign_advance_instruction_secp256k1_eip191(signing_key, nonce, pre, post)` — sign with EIP-191 (envelope, 65-byte sig).
- `sign_advance_instruction_secp256k1_ecdsa(signing_key, nonce, pre, post)` — sign with plain secp256k1 ECDSA (64-byte sig).
- `verify_advance_signature_ed25519(pubkey, nonce, pre, post, fee_payer, signature)` / `verify_advance_signature_secp256k1_ecdsa(...)` / `verify_advance_signature_secp256k1_eip191(...)` / `verify_advance_signature_falcon512(wire_pubkey, ...)` — verify an advance signature fully offline; returns the digest (= next nonce) on success. See [Offline verification](#offline-verification).
- `ed25519_pubkey` / `secp256k1_eip191_eth_address` / `secp256k1_compressed_pubkey` / `falcon512_identity(wire_pubkey)` / `eth_address_from_pubkey` / `eip191_envelope_hash(digest)` — identity/envelope utilities.

Falcon-512 signing is intentionally left to the caller (`solana-falcon512` is verify-only) — pair with an external signer such as `pqcrypto-falcon` and feed the wire-format signature into `create_advance_instruction`.

### TypeScript (`@vector/sdk`)

The TypeScript SDK mirrors the Rust SDK and exposes the same `Scheme` objects (`ED25519`, `EIP191`, `FALCON512`, `SECP256K1`, `WINTERNITZ`, `XMSS`):

- `createRotateSubinstruction(scheme, identity, newPublicKey)` — authorize a Winternitz/XMSS key replacement through Passthrough.
- `findVectorPda(scheme, identity)` — derive the canonical Vector PDA.
- `fetchVectorAccount(connection, scheme, identity)` — fetch and deserialize the 33-byte header.
- `createInitializeEd25519(payer, pubkey)` / `createInitializeEip191(payer, ethAddress)` / `createInitializeSecp256k1(payer, compressedPubkey)` / `createInitializeFalcon512(payer, wirePubkey)` — convenience wrappers.
- `createInitializeInstruction(payer, scheme, identity, initPayload)` — generic init builder.
- `createCloseSubinstruction(scheme, identity, closeTo)` / `createWithdrawSubinstruction(scheme, identity, receiver, lamports)` — sub-instruction builders.
- `createAdvanceInstruction(scheme, identity, signature)` — assemble from precomputed signature (signature only, no embedded payload).
- `createPassthroughInstruction(scheme, identity, subIxs)` — assemble the passthrough instruction that replays `subIxs` under the PDA's signer seeds; include it among the pre/post instructions so the digest commits to it.
- `advanceVectorDigest(scheme, nonce, identity, pre, post, feePayer?)` — recompute the digest.
- `signAdvanceInstructionEd25519(signingKey, nonce, pre, post, feePayer?)` — sign with Ed25519.
- `signAdvanceInstructionEip191(privateKey, nonce, pre, post, feePayer?)` — sign with EIP-191 secp256k1.
- `signAdvanceInstructionSecp256k1(privateKey, nonce, pre, post, feePayer?)` — sign with plain secp256k1 ECDSA.
- `signAdvanceInstructionFalcon512(keypair, nonce, pre, post, feePayer?)` — sign with Falcon-512 (post-quantum) via [`@noble/post-quantum/falcon.js`](https://github.com/paulmillr/noble-post-quantum); plus `falcon512Keygen`, `falcon512PublicKey`.
- `verifyAdvanceSignatureEd25519(pubkey, nonce, pre, post, signature, feePayer?)` / `verifyAdvanceSignatureSecp256k1(...)` / `verifyAdvanceSignatureEip191(...)` / `verifyAdvanceSignatureFalcon512(wirePubkey, ...)` — verify an advance signature fully offline; returns the digest (= next nonce) or throws a named error. Plus `normalizeEip191RecoveryByte(v)` for converting Ethereum tooling's legacy 27/28 recovery byte at assembly time.
- `ed25519Identity` / `eip191Identity` / `secp256k1Identity` / `falcon512Identity(wirePubkey)` / `secp256k1CompressedPubkey` / `ethAddressFromPrivateKey` / `eip191EnvelopeHash(digest)` — identity/envelope utilities.

The TypeScript SDK implements signing for Ed25519, EIP-191, Secp256k1 and Falcon-512. Winternitz and XMSS signing are supplied by the caller. Falcon-512 uses `@noble/post-quantum`'s compressed detached signature zero-padded to the 666-byte wire format `solana-falcon512` reads. The plain Secp256k1 scheme uses [`@noble/curves/secp256k1`](https://github.com/paulmillr/noble-curves) `secp256k1.sign(...).toCompactRawBytes()` for the 64-byte `(r, s)` wire form.

Each scheme is its own importable entrypoint (the npm feature-flag analogue) so a consumer only pulls the crypto it uses: `import { signAdvanceInstructionFalcon512 } from "vector-sdk/falcon512"` (Falcon + PQ lib only) vs `import { ... } from "vector-sdk"` (everything).

The signed digest doubles as the next on-chain nonce, so a successful advance always replaces `nonce` with the digest that authorized it.

## Operational Patterns

Everything below is native protocol behaviour — no extra programs, accounts, or formats. The building blocks are the digest (`SHA256(pre || nonce || identity || post)`), digest-as-next-nonce progression, and the fact that one vector account holds exactly one outstanding nonce.

### Offline verification

Both SDKs ship per-scheme verify functions that recompute the digest from the full instruction layout and check the signature exactly as the on-chain program will — no RPC. A PASS means the transaction will verify on-chain against the same nonce; the returned digest is the account's next nonce.

```rust
use vector_core::verify_advance_signature_ed25519;

let next_nonce = verify_advance_signature_ed25519(
    &pubkey, &nonce, &pre_ixs, &post_ixs, None, signature,
)?;
```

Two caveats, documented on the functions: Ed25519 is checked with `ed25519-dalek` offline while the chain runs `brine-ed25519` (only adversarially malformed signatures can be judged differently — honest signatures verify identically), and the fee payer affects the digest only when its key appears in a committed instruction (message-level flag promotion then folds it in as a writable signer).

### Concurrency

One identity = one vector account = one outstanding pre-signed transaction. Signatures against the same nonce are mutually exclusive: the first to land advances the nonce and permanently orphans the rest. For N concurrent in-flight transactions, register N identities (N accounts under the same scheme program) and treat each as an independent lane.

### Unilateral revocation

An `advance` with empty pre/post instructions is an inert transition: it verifies, installs the next nonce, and does nothing else. Signed at the outstanding nonce, it is a kill-switch — landing it orphans every signature derived from that nonce (see [Invalidation and Forward Exposure](#invalidation-and-forward-exposure)). Pre-sign the inert advance in the same session as the transactions it guards; broadcasting it later requires no further access to the key.

Both SDKs ship this as sugar over the advance signers: `sign_revocation_instruction_ed25519(key, nonce)` / `_secp256k1_ecdsa` / `_secp256k1_eip191` (Rust), `signRevocationInstructionEd25519(key, nonce)` / `Secp256k1` / `Eip191` (TypeScript), plus `revocation_digest(scheme, nonce, identity)` / `revocationDigest(...)` to recompute what they commit to. Verifying one is just the ordinary advance verifier with empty pre/post. The digest commits to the broadcasting transaction's instructions sysvar, so the revocation must be broadcast as a transaction containing **only** the advance instruction — adding so much as a compute-budget ix afterwards invalidates the signature. The three covered schemes fit the default compute budget (~13k/26k/72k CUs); Falcon-512 has no zero-arg sugar by design — sign via the advance signer with a compute-budget pre-instruction committed at sign time, since its ~184k CU inert advance leaves no headroom under the 200k default.

### Ordered pre-signing

The digest returned at sign time **is** the nonce after that advance lands, so a chain of dependent transactions can be pre-signed in one session: sign transaction 1 against the current nonce, transaction 2 against transaction 1's digest, and so on. The chain can only execute in order — transaction 2 cannot become valid until transaction 1 has landed — and an inert advance signed at any link's nonce severs the chain from that point.

### Expiry

A timeout instruction placed inside the signed buffer is committed to by the digest like everything else (see [Transaction Expiration](#transaction-expiration)). Pair pre-signed transactions with a deadline instruction such as [sbpf-asm-timeout](https://github.com/deanmlittle/sbpf-asm-timeout) so a withheld transaction dies on its own instead of waiting for a kill-switch.

## License
MIT
