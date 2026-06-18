/**
 * Migration into the fund-in-PDA model. The common path needs no authority
 * reassignment at all: move SOL into the PDA and create PDA-owned token
 * accounts. An optional in-place `SetAuthority`→PDA path is provided for
 * callers who must keep an existing token account; for STAKE accounts note
 * the runtime forbids changing the withdraw authority under an active lockup —
 * those must wait for lockup expiry (out of scope here).
 *
 * Pair these with {@link scanMigration} to confirm nothing is left behind.
 */
import { Address, SystemProgram, TransactionInstruction } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  associatedTokenAddress,
} from "./wallet.js";

const SYSTEM_PROGRAM_ID = new Address("11111111111111111111111111111111");

/** Move SOL from an existing wallet into the PDA wallet. Old wallet signs. */
export function createMigrateSolInstruction(
  oldWallet: Address,
  pda: Address,
  lamports: number
): TransactionInstruction {
  return SystemProgram.transfer({ fromPubkey: oldWallet, toPubkey: pda, lamports });
}

/** Create the PDA-owned ATA (Associated Token Account `Create`, data = []). */
export function createPdaAtaInstruction(
  payer: Address,
  pda: Address,
  mint: Address,
  tokenProgram: Address = TOKEN_PROGRAM_ID
): TransactionInstruction {
  const ata = associatedTokenAddress(mint, pda, tokenProgram);
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: pda, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: tokenProgram, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([]),
  });
}

/**
 * In-place SPL `SetAuthority` handing a token account's authority to the PDA.
 * data = `[6 (SetAuthority), authorityType, hasNewAuthority(1), newAuthority(32)]`.
 * authorityType 2 = AccountOwner; 0 = MintTokens; 1 = FreezeAccount.
 */
export function createTokenAuthorityReassignment(
  account: Address,
  currentAuthority: Address,
  newAuthorityPda: Address,
  authorityType = 2,
  tokenProgram: Address = TOKEN_PROGRAM_ID
): TransactionInstruction {
  const data = new Uint8Array(1 + 1 + 1 + 32);
  data[0] = 6;
  data[1] = authorityType;
  data[2] = 1; // COption::Some
  data.set(newAuthorityPda.toBytes(), 3);
  return new TransactionInstruction({
    programId: tokenProgram,
    keys: [
      { pubkey: account, isSigner: false, isWritable: true },
      { pubkey: currentAuthority, isSigner: true, isWritable: false },
    ],
    data: Buffer.from(data),
  });
}
