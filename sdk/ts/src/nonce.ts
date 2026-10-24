/**
 * Durable nonces on Vector, in `@solana/web3.js`'s shapes. A nonce account
 * is created with {@link createNonceAccount}, its nonce read with
 * {@link getNonce} and it is closed with {@link closeNonceAccount}. A {@link NoncedTransaction} takes the
 * instructions a durable nonce transaction would, naming the nonce
 * authority; the authority signs it over the nonce, offline.
 *
 * Whoever submits it handles a plain `Transaction`: set a recent blockhash,
 * then sign with the fee payer and any other signer.
 *
 * ```ts
 * const nonce = await getNonce(connection, nonceAccount);
 * const tx = new NoncedTransaction({
 *   feePayer,
 *   nonceInfo: { nonce, nonceAccount, authority: authority.address },
 * }).add(SystemProgram.transfer({ fromPubkey: authority.address, toPubkey, lamports }));
 * await tx.partialSign(authority);
 * const bytes = await tx.serialize({ requireAllSignatures: false });
 *
 * const later = Transaction.from(bytes);
 * later.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
 * await later.partialSign(payer);
 * await connection.sendRawTransaction(await later.serialize());
 * ```
 */
import {
  Address,
  Connection,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  type Signer,
} from "@solana/web3.js";

import { advanceMessage, signerDigest } from "./digest.js";
import {
  createCloseSubinstruction,
  createInitializeNonceInstruction,
  createMultiAdvanceInstruction,
  createMultiPassthroughInstruction,
} from "./instructions.js";
import {
  findSystemPda,
  findVectorPda,
  NONCE_ACCOUNT_LEN,
  NonceAccount,
  PROGRAM_ID,
  signedNonce,
} from "./scheme.js";
import { ED25519 } from "./schemes/ed25519.js";

/**
 * The account that takes `authority`'s place: a System account, so it holds
 * SOL and is the owner or authority of tokens, mints and stake, as the key
 * was. Only a message the authority signs moves it.
 */
export function systemAccount(authority: Address): Address {
  return findSystemPda(findVectorPda(ED25519, authority.toBytes())[0])[0];
}

/**
 * Create a nonce account for `authorizedPubkey`, as
 * `SystemProgram.createNonceAccount`: `noncePubkey` signs, `fromPubkey` funds
 * it. The authority's vector account must exist
 * (`createInitializeEd25519`).
 */
export function createNonceAccount(params: {
  fromPubkey: Address;
  noncePubkey: Address;
  authorizedPubkey: Address;
  lamports: number | bigint;
}): Transaction {
  const { fromPubkey, noncePubkey, authorizedPubkey, lamports } = params;
  return new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey,
      newAccountPubkey: noncePubkey,
      lamports,
      space: NONCE_ACCOUNT_LEN,
      programId: PROGRAM_ID,
    }),
    createInitializeNonceInstruction(
      noncePubkey,
      findVectorPda(ED25519, authorizedPubkey.toBytes())[0]
    )
  );
}

/**
 * What the next message signed over `nonceAccount` is signed over, as
 * `connection.getNonce(..).nonce`: {@link signedNonce} of its nonce and its
 * vector's own.
 */
export async function getNonce(connection: Connection, nonceAccount: Address): Promise<Uint8Array> {
  const info = await connection.getAccountInfo(nonceAccount);
  if (!info) throw new Error("Nonce account not found");
  const { nonce, vector } = NonceAccount.fromAccountData(info.data);
  const vectorInfo = await connection.getAccountInfo(vector);
  if (!vectorInfo) throw new Error("Vector account not found");
  return signedNonce(nonce, vectorInfo.data.subarray(0, 32));
}

/**
 * Close a nonce account of `authorizedPubkey`, sending its lamports to
 * `toPubkey`: `SystemProgram.nonceWithdraw` for all of them. Add it to a
 * {@link NoncedTransaction}, from the slot after the account was created.
 */
export function closeNonceAccount(params: {
  noncePubkey: Address;
  authorizedPubkey: Address;
  toPubkey: Address;
}): TransactionInstruction {
  const { noncePubkey, authorizedPubkey, toPubkey } = params;
  return createCloseSubinstruction(ED25519, authorizedPubkey.toBytes(), toPubkey, noncePubkey);
}

/** What a {@link NoncedTransaction} signs over: web3.js's `NonceInformation`. */
export type NoncedInformation = {
  /** From {@link getNonce}. */
  nonce: Uint8Array;
  nonceAccount: Address;
  authority: Address;
};

/**
 * A `Transaction` the nonce authority signs over a nonce. Its instructions
 * name the authority, as under durable nonces; each such account becomes
 * {@link systemAccount}. Vector signs as that, and as the authority's vector.
 *
 * The authority signs alone, and first: its signature replaces the
 * instructions with Vector's `Advance` and `Passthrough`. The fee payer and
 * any other signer then sign over a recent blockhash.
 */
export class NoncedTransaction extends Transaction {
  readonly noncedInfo: NoncedInformation;
  #instructions?: TransactionInstruction[];

  constructor({ feePayer, nonceInfo }: { feePayer?: Address; nonceInfo: NoncedInformation }) {
    super({ feePayer });
    this.noncedInfo = nonceInfo;
  }

  override async partialSign(...signers: Signer[]): Promise<void> {
    if (!(await this.#signAsAuthority(signers))) await super.partialSign(...signers);
  }

  override async sign(...signers: Signer[]): Promise<void> {
    if (!(await this.#signAsAuthority(signers))) await super.sign(...signers);
  }

  async #signAsAuthority(signers: Signer[]): Promise<boolean> {
    const { nonce, nonceAccount, authority } = this.noncedInfo;
    if (!signers.some((signer) => signer.address.equals(authority))) return false;
    if (signers.length !== 1) {
      throw new Error(
        "The nonce authority signs alone: over the nonce, the others over a recent blockhash"
      );
    }

    this.#instructions ??= this.instructions;
    const acting = systemAccount(authority);
    const instructions = this.#instructions.map(
      ({ programId, keys, data }) =>
        new TransactionInstruction({
          programId,
          data,
          keys: keys.map((key) => (key.pubkey.equals(authority) ? { ...key, pubkey: acting } : key)),
        })
    );
    const identity = authority.toBytes();
    const post = instructions.length
      ? [
          createMultiPassthroughInstruction(
            [
              { scheme: ED25519, identity, system: true },
              { scheme: ED25519, identity },
            ],
            instructions
          ),
        ]
      : [];
    const signer = { scheme: ED25519, identity, nonceAccount };
    const digest = signerDigest(
      advanceMessage([signer], [], post, this.feePayer),
      nonce,
      findVectorPda(ED25519, identity)[0]
    );
    const signature = await signers[0].signBytes(digest);

    this.instructions = [createMultiAdvanceInstruction([{ ...signer, signature }]), ...post];
    // Lets it serialize; whoever submits sets a recent blockhash.
    this.recentBlockhash ??= new Address(nonce).toString() as NonNullable<Transaction["recentBlockhash"]>;
    return true;
  }
}
