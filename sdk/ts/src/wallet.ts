/**
 * Fund-in-PDA wallet helpers. The Vector PDA *is* the wallet: it holds native
 * SOL directly and owns SPL token accounts, and spends are authorized by an
 * offline Vector signature (see {@link Vector}). ATA derivation and the SPL
 * instructions are built by hand so the SDK needs no `@solana/spl-token`.
 *
 * Spends themselves go through the facade — e.g. `v.authorize(nonce,
 * createWithdrawSubinstruction(...))` for SOL, or `v.authorize(nonce,
 * createSplTransferIx(...))` for tokens.
 */
import { Address, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import { findProgramAddressSync, writeU64LE } from "./scheme.js";

export const TOKEN_PROGRAM_ID = new Address(
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
);
export const TOKEN_2022_PROGRAM_ID = new Address(
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
);
export const ASSOCIATED_TOKEN_PROGRAM_ID = new Address(
  "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
);

/** Derive the off-curve ATA for `mint` owned by `owner` (a PDA is fine). */
export function associatedTokenAddress(
  mint: Address,
  owner: Address,
  tokenProgram: Address = TOKEN_PROGRAM_ID
): Address {
  const [ata] = findProgramAddressSync(
    [owner.toBytes(), tokenProgram.toBytes(), mint.toBytes()],
    ASSOCIATED_TOKEN_PROGRAM_ID
  );
  return ata;
}

/** Move SOL into the PDA wallet (a plain System transfer). */
export function createFundWalletInstruction(
  payer: Address,
  pda: Address,
  lamports: number
): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: payer, toPubkey: pda, lamports });
}

/**
 * SPL Token `Transfer`, built by hand. `authority` is typically the Vector
 * PDA; inside a passthrough its signer flag is cleared and the runtime
 * promotes the PDA to signer at CPI time. Pass {@link TOKEN_2022_PROGRAM_ID}
 * for Token-2022 mints.
 */
export function createSplTransferIx(
  source: Address,
  destination: Address,
  authority: Address,
  amount: bigint,
  tokenProgram: Address = TOKEN_PROGRAM_ID
): TransactionInstruction {
  const data = new Uint8Array(1 + 8);
  data[0] = 3; // Transfer
  writeU64LE(data, amount, 1);
  return new TransactionInstruction({
    programId: tokenProgram,
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
