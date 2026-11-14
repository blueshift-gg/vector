/**
 * V1 transactions (SIMD-0385), the transaction format Vector is built for:
 * up to 4,096 bytes, which ML-DSA-44, XMSS and an `advance` with several
 * signers need, and resource limits carried in the message instead of
 * Compute Budget instructions.
 *
 * The limits are not instructions, so they are not in the instructions
 * sysvar and no signer signs them: whoever submits can raise or lower them
 * without new signatures. The fee payer still signs the transaction itself.
 */
import {
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

/** The most compute a transaction may request. */
export const MAX_COMPUTE_UNIT_LIMIT = 1_400_000;

/** The most account data a transaction may load: 64 MiB. */
export const MAX_LOADED_ACCOUNTS_DATA_SIZE = 64 * 1024 * 1024;

/**
 * A V1 transaction's limits. Unlike legacy and v0 transactions, a V1
 * transaction gets nothing for a limit it leaves out: no compute, and no
 * account data, so not even the program loads.
 */
export type V1Limits = {
  /** Compute units for the whole transaction. Default {@link MAX_COMPUTE_UNIT_LIMIT}. */
  computeUnitLimit?: number;
  /**
   * Bytes of account data the transaction may load, programs included.
   * Default {@link MAX_LOADED_ACCOUNTS_DATA_SIZE}.
   */
  loadedAccountsDataSizeLimit?: number;
  /** Heap frame size in bytes. Default: the runtime's. */
  heapSize?: number;
  /** Total priority fee in lamports (not per compute unit). Default none. */
  priorityFeeLamports?: bigint;
};

/**
 * The default limits: the most a transaction may request. They never fail
 * an `advance` for want of compute or account data; tighter limits help a
 * leader schedule the transaction.
 */
export const DEFAULT_V1_LIMITS = {
  computeUnitLimit: MAX_COMPUTE_UNIT_LIMIT,
  loadedAccountsDataSizeLimit: MAX_LOADED_ACCOUNTS_DATA_SIZE,
} as const;

/**
 * Build an unsigned V1 transaction of `instructions`, paid by `feePayer`,
 * with {@link DEFAULT_V1_LIMITS} unless `limits` says otherwise. Sign it
 * with the fee payer (and any other signers): `await tx.sign([feePayer])`.
 *
 * The `advance`'s digest covers the instructions in this order and the fee
 * payer's flags, so build the signatures over the same `instructions` and
 * `feePayer`.
 */
export function createV1Transaction(params: {
  feePayer: PublicKey;
  instructions: TransactionInstruction[];
  recentBlockhash: string;
  limits?: V1Limits;
}): VersionedTransaction {
  const { feePayer, instructions, recentBlockhash, limits } = params;
  const message = new TransactionMessage({
    payerKey: feePayer,
    instructions,
    recentBlockhash: recentBlockhash as TransactionMessage["recentBlockhash"],
  }).compileToV1Message({ ...DEFAULT_V1_LIMITS, ...limits });
  return new VersionedTransaction(message);
}
