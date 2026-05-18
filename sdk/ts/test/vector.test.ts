/**
 * Integration tests for the Vector TypeScript SDK.
 *
 * Prerequisites:
 *   1. Build the programs:
 *        for s in ed25519 eip191 falcon512 secp256k1; do \
 *          cargo build-sbf --manifest-path programs/$s/Cargo.toml; done
 *   2. Start validator:    bun run validator
 *   3. Run tests:          bun vitest run
 *
 * Each scheme is its own program; the SDK addresses them via `Scheme`
 * objects (ED25519 / EIP191 / SECP256K1 / FALCON512). Identities are raw
 * byte arrays (pubkey/address), not 32-byte PublicKeys.
 */
import { describe, test, expect, beforeAll, afterAll } from "vitest";
import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  AuthorityType,
  createAssociatedTokenAccountInstruction,
  createMintToInstruction,
  createSetAuthorityInstruction,
  getAccount,
  getAssociatedTokenAddressSync,
  getMint,
  createInitializeMint2Instruction,
  MINT_SIZE,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";

import {
  Scheme,
  ED25519,
  EIP191,
  SECP256K1,
  FALCON512,
  findVectorPda,
  fetchVectorAccount,
  createInitializeEd25519,
  createInitializeEip191,
  createInitializeSecp256k1,
  createInitializeFalcon512,
  createCloseSubinstruction,
  createWithdrawSubinstruction,
  signAdvanceInstruction,
  signAdvanceInstructionEip191,
  signAdvanceInstructionSecp256k1,
  signAdvanceInstructionFalcon512,
  ed25519Identity,
  eip191Identity,
  secp256k1Identity,
  falcon512Keygen,
  falcon512Identity,
  advanceVectorDigest,
} from "../src/index.js";

// ── Constants ────────────────────────────────────────────────────────

const RPC_URL = "http://localhost:8899";

// Ed25519 test key
const SIGNER_KEY = new Uint8Array(32);
SIGNER_KEY[31] = 0x01;
const ED25519_IDENTITY = ed25519Identity(SIGNER_KEY);

// secp256k1 test key (same bytes, different curve)
const SECP_KEY = new Uint8Array(32);
SECP_KEY[31] = 0x01;
const EIP191_IDENTITY = eip191Identity(SECP_KEY);
const SECP256K1_IDENTITY = secp256k1Identity(SECP_KEY);

// Falcon-512 deterministic test keypair (48-byte noble keygen seed) so the
// PDA is stable across the block and across runs against a fresh validator.
const FALCON_SEED = new Uint8Array(48);
FALCON_SEED[47] = 0x01;
const { secretKey: FALCON_SK, publicKey: FALCON_PK } =
  falcon512Keygen(FALCON_SEED);
const FALCON_IDENTITY = falcon512Identity(FALCON_PK);

// Fixed fee payer — funded via --mint flag on solana-test-validator.
const FEE_PAYER_SEED = new Uint8Array(32);
FEE_PAYER_SEED[0] = 1;

// ── Helpers ──────────────────────────────────────────────────────────

function explorerLink(signature: string): string {
  return `https://explorer.solana.com/tx/${signature}?cluster=custom&customUrl=${RPC_URL}`;
}

async function sendTx(
  connection: Connection,
  tx: Transaction,
  signers: Keypair[]
): Promise<string> {
  const sig = await sendAndConfirmTransaction(connection, tx, signers);
  console.log(explorerLink(sig));
  return sig;
}

/**
 * SPL mint-authority round-trip: temporarily hands a mint's authority from
 * the vector PDA to an EOA, mints, and hands it back — all authorized by a
 * single signed `advance` whose payload is the PDA→EOA `set_authority` CPI,
 * with the `mint_to` + EOA→PDA `set_authority` as committed post-instructions.
 * Mirrors the Rust `run_round_trip_spl`. Returns the advanced nonce.
 *
 * `signAdvance` is the scheme's signer closure already bound to its key and
 * the fee payer: `(nonce, sub, pre, post) => advanceInstruction`.
 */
async function splMintAuthorityRoundTrip(
  connection: Connection,
  feePayer: Keypair,
  scheme: Scheme,
  identity: Uint8Array,
  vectorPda: PublicKey,
  currentNonce: Uint8Array,
  signAdvance: (
    nonce: Uint8Array,
    sub: TransactionInstruction[],
    pre: TransactionInstruction[],
    post: TransactionInstruction[]
  ) => TransactionInstruction
): Promise<Uint8Array> {
  // 1. Create a mint with authority = vectorPda.
  const mint = Keypair.generate();
  const rentExempt = await connection.getMinimumBalanceForRentExemption(
    MINT_SIZE
  );
  const createMintTx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: feePayer.publicKey,
      newAccountPubkey: mint.publicKey,
      space: MINT_SIZE,
      lamports: rentExempt,
      programId: TOKEN_PROGRAM_ID,
    }),
    createInitializeMint2Instruction(mint.publicKey, 6, vectorPda, null)
  );
  await sendAndConfirmTransaction(connection, createMintTx, [feePayer, mint]);

  // 2. Create an associated token account for the fee payer.
  const destination = getAssociatedTokenAddressSync(
    mint.publicKey,
    feePayer.publicKey
  );
  await sendAndConfirmTransaction(
    connection,
    new Transaction().add(
      createAssociatedTokenAccountInstruction(
        feePayer.publicKey,
        destination,
        feePayer.publicKey,
        mint.publicKey
      )
    ),
    [feePayer]
  );

  // 3. [advance(CPI: set_authority PDA→EOA), mint_to, set_authority EOA→PDA]
  const pdaToEoa = createSetAuthorityInstruction(
    mint.publicKey,
    vectorPda,
    AuthorityType.MintTokens,
    feePayer.publicKey
  );
  const mintToIx = createMintToInstruction(
    mint.publicKey,
    destination,
    feePayer.publicKey,
    10_000
  );
  const eoaToPda = createSetAuthorityInstruction(
    mint.publicKey,
    feePayer.publicKey,
    AuthorityType.MintTokens,
    vectorPda
  );

  // 4. Sign + submit. The advance commits to mint_to + EOA→PDA as
  //    post-instructions even though it only CPI-replays PDA→EOA.
  const advanceIx = signAdvance(
    currentNonce,
    [pdaToEoa],
    [],
    [mintToIx, eoaToPda]
  );
  await sendTx(
    connection,
    new Transaction().add(advanceIx, mintToIx, eoaToPda),
    [feePayer]
  );

  // 5. Verify: nonce advanced to the digest, tokens minted, authority back.
  const nextNonce = advanceVectorDigest(
    scheme,
    currentNonce,
    identity,
    [pdaToEoa],
    [],
    [mintToIx, eoaToPda],
    feePayer.publicKey
  );

  const account = await fetchVectorAccount(connection, scheme, identity);
  expect(Buffer.from(account.nonce)).toEqual(Buffer.from(nextNonce));

  const tokenInfo = await getAccount(connection, destination);
  expect(tokenInfo.amount).toBe(BigInt(10_000));

  const mintInfo = await getMint(connection, mint.publicKey);
  expect(mintInfo.mintAuthority!.equals(vectorPda)).toBe(true);

  return nextNonce;
}

// ── Ed25519 Tests ────────────────────────────────────────────────────

describe("vector-ed25519", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let vectorBump: number;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");
    feePayer = Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(ED25519, ED25519_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize vector account", async () => {
    const ix = createInitializeEd25519(feePayer.publicKey, ED25519_IDENTITY);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      ED25519,
      ED25519_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      ED25519,
      ED25519_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, sub, pre, post) =>
        signAdvanceInstruction(
          SIGNER_KEY,
          nonce,
          sub,
          pre,
          post,
          feePayer.publicKey
        )
    );
  });

  test("withdraw lamports via advance", async () => {
    // A freshly-initialized account holds exactly its rent-exempt minimum,
    // and on-chain `withdraw` refuses to drop below that floor. Top the PDA
    // up first so there are withdrawable lamports above rent-exemption.
    const topUp = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: feePayer.publicKey,
        toPubkey: vectorPda,
        lamports: 5_000_000,
      })
    );
    await sendAndConfirmTransaction(connection, topUp, [feePayer]);

    const before = await connection.getAccountInfo(vectorPda);
    expect(before).not.toBeNull();
    const startingLamports = before!.lamports;
    const withdrawAmount = 1_000n;

    const withdrawSub = createWithdrawSubinstruction(
      ED25519,
      ED25519_IDENTITY,
      feePayer.publicKey,
      withdrawAmount
    );
    const advanceIx = signAdvanceInstruction(
      SIGNER_KEY,
      currentNonce,
      [withdrawSub],
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      ED25519,
      currentNonce,
      ED25519_IDENTITY,
      [withdrawSub],
      [],
      [],
      feePayer.publicKey
    );

    const after = await connection.getAccountInfo(vectorPda);
    expect(after).not.toBeNull();
    expect(after!.lamports).toBe(startingLamports - Number(withdrawAmount));
  });

  test("close vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      ED25519,
      ED25519_IDENTITY,
      feePayer.publicKey
    );
    const advanceIx = signAdvanceInstruction(
      SIGNER_KEY,
      currentNonce,
      [closeSub],
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});

// ── EIP-191 Tests ────────────────────────────────────────────────────

describe("vector-eip191", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let vectorBump: number;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");
    feePayer = Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(EIP191, EIP191_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize eip191 vector account", async () => {
    const ix = createInitializeEip191(feePayer.publicKey, EIP191_IDENTITY);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      EIP191,
      EIP191_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionEip191(
      SECP_KEY,
      currentNonce,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      EIP191,
      currentNonce,
      EIP191_IDENTITY,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const account = await fetchVectorAccount(
      connection,
      EIP191,
      EIP191_IDENTITY
    );
    expect(Buffer.from(account.nonce)).toEqual(Buffer.from(currentNonce));
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      EIP191,
      EIP191_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, sub, pre, post) =>
        signAdvanceInstructionEip191(
          SECP_KEY,
          nonce,
          sub,
          pre,
          post,
          feePayer.publicKey
        )
    );
  });

  test("close eip191 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      EIP191,
      EIP191_IDENTITY,
      feePayer.publicKey
    );
    const advanceIx = signAdvanceInstructionEip191(
      SECP_KEY,
      currentNonce,
      [closeSub],
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});

// ── Secp256k1 (plain ECDSA) Tests ────────────────────────────────────

describe("vector-secp256k1", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let vectorBump: number;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");
    feePayer = Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(SECP256K1, SECP256K1_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  test("initialize secp256k1 vector account", async () => {
    const ix = createInitializeSecp256k1(
      feePayer.publicKey,
      SECP256K1_IDENTITY
    );
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      SECP256K1,
      SECP256K1_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionSecp256k1(
      SECP_KEY,
      currentNonce,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      SECP256K1,
      currentNonce,
      SECP256K1_IDENTITY,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const account = await fetchVectorAccount(
      connection,
      SECP256K1,
      SECP256K1_IDENTITY
    );
    expect(Buffer.from(account.nonce)).toEqual(Buffer.from(currentNonce));
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      SECP256K1,
      SECP256K1_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, sub, pre, post) =>
        signAdvanceInstructionSecp256k1(
          SECP_KEY,
          nonce,
          sub,
          pre,
          post,
          feePayer.publicKey
        )
    );
  });

  test("close secp256k1 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      SECP256K1,
      SECP256K1_IDENTITY,
      feePayer.publicKey
    );
    const advanceIx = signAdvanceInstructionSecp256k1(
      SECP_KEY,
      currentNonce,
      [closeSub],
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});

// ── Falcon-512 (post-quantum) Tests ──────────────────────────────────

describe("vector-falcon512", () => {
  let connection: Connection;
  let feePayer: Keypair;
  let vectorPda: PublicKey;
  let vectorBump: number;
  let currentNonce: Uint8Array;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");
    feePayer = Keypair.fromSeed(FEE_PAYER_SEED);

    [vectorPda, vectorBump] = findVectorPda(FALCON512, FALCON_IDENTITY);
  });

  afterAll(() => {
    (connection as any)._rpcWebSocket?.close();
  });

  // Falcon-512 is single-step: its 1090-byte account fits one CPI
  // CreateAccount, so `initialize` registers it in a single call (the
  // wire pubkey is hashed + prepared on-chain at init).
  test("initialize falcon512 vector account", async () => {
    const ix = createInitializeFalcon512(feePayer.publicKey, FALCON_PK);
    const tx = new Transaction().add(ix);
    await sendTx(connection, tx, [feePayer]);

    const account = await fetchVectorAccount(
      connection,
      FALCON512,
      FALCON_IDENTITY
    );
    expect(account.bump).toBe(vectorBump);

    currentNonce = new Uint8Array(account.nonce);
  });

  // Falcon advance verifies via the prepared pubkey (~184k CU, within the
  // 200k default per-instruction budget).
  test("advance with empty payload", async () => {
    const advanceIx = signAdvanceInstructionFalcon512(
      FALCON_SK,
      currentNonce,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    currentNonce = advanceVectorDigest(
      FALCON512,
      currentNonce,
      FALCON_IDENTITY,
      [],
      [],
      [],
      feePayer.publicKey
    );

    const account = await fetchVectorAccount(
      connection,
      FALCON512,
      FALCON_IDENTITY
    );
    expect(Buffer.from(account.nonce)).toEqual(Buffer.from(currentNonce));
  });

  test("advance round-trips SPL mint authority", async () => {
    currentNonce = await splMintAuthorityRoundTrip(
      connection,
      feePayer,
      FALCON512,
      FALCON_IDENTITY,
      vectorPda,
      currentNonce,
      (nonce, sub, pre, post) =>
        signAdvanceInstructionFalcon512(
          FALCON_SK,
          nonce,
          sub,
          pre,
          post,
          feePayer.publicKey
        )
    );
  });

  test("close falcon512 vector account via advance", async () => {
    const closeSub = createCloseSubinstruction(
      FALCON512,
      FALCON_IDENTITY,
      feePayer.publicKey
    );
    const advanceIx = signAdvanceInstructionFalcon512(
      FALCON_SK,
      currentNonce,
      [closeSub],
      [],
      [],
      feePayer.publicKey
    );
    const tx = new Transaction().add(advanceIx);
    await sendTx(connection, tx, [feePayer]);

    const info = await connection.getAccountInfo(vectorPda);
    expect(info).toBeNull();
  });
});
