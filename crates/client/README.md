# vector-client

Async RPC client, fund-in-PDA migration builders, and the migration scanner for
Vector. All offline signing stays in `vector-core`; this crate adds the I/O layer
(tokio + `solana-rpc-client`).

```toml
[dependencies]
vector-client = "0.1"   # pulls vector-core; ed25519/secp256k1/eip191 by default
```

## RPC client

```rust
use vector_client::read::VectorClient;
use vector_core::{Ed25519, Op, Vector};

let client = VectorClient::new("https://api.mainnet-beta.solana.com");

// Read the current nonce from the PDA.
let nonce: [u8; 32] = client.nonce(&pda).await?;

// Sign offline with vector-core, then broadcast.
let v = Vector::new(Ed25519::from_seed(&seed));
let art = v.authorize(&nonce, Op::Inert);
let sig = client.send_artifact(&art, &fee_payer_keypair).await?;
```

`VectorClient::status` returns the full `VectorAccount` header (nonce + bump).

## Fund-in-PDA migration builders

Instruction builders for migrating assets from an old keypair authority to a
Vector PDA. No spl-token or spl-associated-token-account crates are needed.

```rust
use vector_client::migrate::{
    associated_token_address,
    create_fund_wallet_instruction,   // payer → pda (SOL)
    create_migrate_sol_instruction,   // old_wallet → pda (SOL, signer = old key)
    create_pda_ata_instruction,       // create ATA owned by the PDA
    create_spl_transfer_ix,           // SPL Transfer (discriminator 3)
    create_token_authority_reassignment, // SPL SetAuthority (discriminator 6)
};

// Derive the ATA for (mint, owner=pda, TOKEN_PROGRAM_ID).
let ata = associated_token_address(&mint, &pda, &TOKEN_PROGRAM_ID);
```

## Migration scanner

Audit every asset class still controlled by an old keypair. Returns a
`MigrationReport`; `report.complete` is `true` once nothing controllable remains.

```rust
use vector_client::scan::{ScanOptions, MigrationReport};

let opts = ScanOptions {
    owner: old_keypair_address,
    pda:   vector_pda,
    mints: vec![my_mint],      // declared mints to check authority
    accounts: vec![],          // generic accounts with authority at a given offset
    dust_lamports: 5000,
};

let report: MigrationReport = client.scan_migration(&opts).await?;
println!("complete: {}", report.complete);
for item in &report.unmigrated {
    println!("  {:?} {}", item.kind, item.address);
}
```

Audited asset classes: native SOL, SPL + Token-2022 accounts, stake accounts
(staker + withdraw authority), declared mint authorities, freeze authorities, and
generic accounts with a 32-byte authority at a specified offset.
