//! Durable transaction nonce helpers, on Vector.
//!
//! The shapes of `solana-system-interface`, `Message::new_with_nonce`,
//! `solana-nonce` and `solana-rpc-client-nonce-utils`, for nonce accounts that
//! keep working once durable nonces are removed. A cold key keeps its role as
//! the nonce authority: it signs offline over a nonce it read from a nonce
//! account, and anyone pays for and submits the transaction later.
//!
//! What moves: the authority's SOL, tokens, mint, freeze and stake
//! authorities, once, to its [`system_account`], a System account like any
//! wallet. Instructions keep naming the authority;
//! [`NoncedMessage`] puts its system account in its place, and the program
//! signs for it. The submitted transaction carries a recent blockhash, so it
//! expires; the signature does not, until its nonce moves.
//!
//! ```ignore
//! // Once, as with durable nonces:
//! let ixs = create_nonce_account(&payer, &nonce.pubkey(), &authority.pubkey(), rent);
//!
//! // Offline, the cold key signs over the nonce:
//! let transfer = transfer(&authority.pubkey(), &to, lamports);
//! let message = NoncedMessage::new_with_nonce(vec![transfer], Some(&payer), &nonce.pubkey(), &authority.pubkey());
//! let accounts = rpc.get_multiple_accounts(&[nonce.pubkey(), vector(&authority.pubkey())])?;
//! let hash = data_from_account(accounts[0].as_ref()?, accounts[1].as_ref()?)?.blockhash();
//! let mut tx = NoncedTransaction::new_unsigned(message);
//! tx.try_partial_sign(&[&authority], hash)?;
//! let bytes = bincode::serialize(&tx)?;
//!
//! // Later, anywhere, a plain `Transaction`: the fee payer and any other
//! // signer sign over a recent blockhash.
//! let mut tx: Transaction = bincode::deserialize(&bytes)?;
//! tx.try_partial_sign(&[&payer], rpc.get_latest_blockhash()?)?;
//! rpc.send_and_confirm_transaction(&tx)?;
//! ```

use serde::{Serialize, Serializer};
use solana_account::ReadableAccount;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::{signers::Signers, Signer, SignerError};
use solana_system_interface::instruction::create_account;
use solana_transaction::Transaction;
use vector_core::{
    advance_message, create_close_nonce_subinstruction, create_initialize_nonce_instruction,
    create_multi_advance_instruction, create_multi_passthrough_instruction, find_system_pda,
    find_vector_pda, signed_nonce, signer_digest, verify_advance_signature, AdvanceSigner,
    NonceAccount, PassthroughSigner, ED25519, PROGRAM_ID,
};

/// Why a nonce account could not be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid account owner")]
    InvalidAccountOwner,
    #[error("unexpected account data size")]
    UnexpectedDataSize,
    #[error("{provided} is not the nonce authority: the nonce account belongs to vector {vector}")]
    InvalidAuthority { provided: Pubkey, vector: Pubkey },
    #[error("invalid state for requested operation")]
    InvalidStateForOperation,
    #[error("the signature does not verify over the message and nonce")]
    InvalidSignature,
}

/// The vector account of `authority`, an Ed25519 key: it holds the key, and
/// signs for its [`system_account`].
pub fn vector(authority: &Pubkey) -> Pubkey {
    find_vector_pda(&ED25519, authority.as_ref()).0
}

/// The account that takes `authority`'s place: a System account, so it holds
/// SOL and is the owner or authority of tokens, mints and stake, as the key
/// was. Only a message the authority signs moves it.
pub fn system_account(authority: &Pubkey) -> Pubkey {
    find_system_pda(&vector(authority)).0
}

/// Create a nonce account for `authority`, the System program's
/// `create_nonce_account`: `nonce_pubkey` signs, `from_pubkey` funds it with
/// `lamports` (rent for [`NonceAccount::LEN`] bytes). The authority's vector
/// account must exist (`vector_core::create_initialize_ed25519`).
pub fn create_nonce_account(
    from_pubkey: &Pubkey,
    nonce_pubkey: &Pubkey,
    authority: &Pubkey,
    lamports: u64,
) -> Vec<Instruction> {
    vec![
        create_account(
            from_pubkey,
            nonce_pubkey,
            lamports,
            NonceAccount::LEN as u64,
            &PROGRAM_ID,
        ),
        create_initialize_nonce_instruction(nonce_pubkey, &vector(authority)),
    ]
}

/// What a nonce account holds: `solana_nonce::state::State`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Initialized(Data),
}

/// An initialized nonce account: `solana_nonce::state::Data`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// The vector account whose key advances the nonce: [`vector`] of the
    /// nonce authority.
    pub vector: Pubkey,
    /// What the next message signed over this account is signed over:
    /// [`signed_nonce`] of the nonce account's nonce and the vector's own.
    /// Moving the vector's own nonce changes it, cancelling what was signed.
    pub durable_nonce: Hash,
}

impl Data {
    /// The nonce, under the name durable nonce users read it by.
    pub fn blockhash(&self) -> Hash {
        self.durable_nonce
    }

    /// Whether `authority` signs for this nonce account.
    pub fn is_authority(&self, authority: &Pubkey) -> bool {
        self.vector == vector(authority)
    }
}

/// Check that `account` is a nonce account: the Vector program's, and
/// [`NonceAccount::LEN`] bytes.
pub fn account_identity_ok<T: ReadableAccount>(account: &T) -> Result<(), Error> {
    if account.owner() != &PROGRAM_ID {
        Err(Error::InvalidAccountOwner)
    } else if account.data().len() != NonceAccount::LEN {
        Err(Error::UnexpectedDataSize)
    } else {
        Ok(())
    }
}

/// Read the [`State`] of a nonce account, with `vector_account` its
/// vector's account, whose own nonce it signs over too:
/// [`State::Uninitialized`] if it was created but `InitializeNonce` has not
/// run. A wrong vector account gives a nonce no signature lands over.
pub fn state_from_account<T: ReadableAccount>(
    account: &T,
    vector_account: &T,
) -> Result<State, Error> {
    account_identity_ok(account)?;
    if vector_account.owner() != &PROGRAM_ID {
        return Err(Error::InvalidAccountOwner);
    }
    // nonce[32] || vector[32] || created slot[8]
    let (&[nonce, vector], _) = account.data().as_chunks() else {
        return Err(Error::UnexpectedDataSize);
    };
    let Some((vector_nonce, _)) = vector_account.data().split_first_chunk() else {
        return Err(Error::UnexpectedDataSize);
    };
    // No vector is at the zero address.
    Ok(if vector == [0; 32] {
        State::Uninitialized
    } else {
        State::Initialized(Data {
            vector: Pubkey::new_from_array(vector),
            durable_nonce: Hash::new_from_array(signed_nonce(&nonce, vector_nonce)),
        })
    })
}

/// Read the [`Data`] of a nonce account, as [`state_from_account`].
pub fn data_from_account<T: ReadableAccount>(
    account: &T,
    vector_account: &T,
) -> Result<Data, Error> {
    state_from_account(account, vector_account)
        .and_then(|ref state| data_from_state(state).cloned())
}

/// Close `nonce_pubkey`, a nonce account of `authority`, and send its
/// lamports to `to_pubkey`: the System program's `withdraw_nonce_account`,
/// for all its lamports. Sign it in a [`NoncedMessage`], from the slot after
/// it was created.
pub fn close_nonce_account(
    nonce_pubkey: &Pubkey,
    authority: &Pubkey,
    to_pubkey: &Pubkey,
) -> Instruction {
    create_close_nonce_subinstruction(&ED25519, authority.as_ref(), nonce_pubkey, to_pubkey)
}

/// The [`Data`] of an initialized [`State`].
pub fn data_from_state(state: &State) -> Result<&Data, Error> {
    match state {
        State::Uninitialized => Err(Error::InvalidStateForOperation),
        State::Initialized(data) => Ok(data),
    }
}

/// Instructions an authority signs over a nonce, the
/// `Message::new_with_nonce` of durable nonces. Every account that is the
/// authority becomes its [`system_account`]; the program signs as that and
/// as the authority's [`vector`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncedMessage {
    authority: Pubkey,
    nonce_account: Pubkey,
    fee_payer: Option<Pubkey>,
    /// The `Passthrough` running the instructions; none for a message that
    /// only moves the nonce.
    passthrough: Option<Instruction>,
}

impl NoncedMessage {
    /// Sign `instructions` with `nonce_authority` over `nonce_account`.
    ///
    /// `payer` pays for the transaction, as with `Message::new_with_nonce`.
    /// The signature covers it only when it is also an account of the
    /// instructions.
    ///
    /// With no instructions, the message only moves the nonce: like
    /// `advance_nonce_account`, it cancels every message signed over it.
    pub fn new_with_nonce(
        instructions: Vec<Instruction>,
        payer: Option<&Pubkey>,
        nonce_account: &Pubkey,
        nonce_authority: &Pubkey,
    ) -> Self {
        let acting = system_account(nonce_authority);
        let instructions: Vec<_> = instructions
            .into_iter()
            .map(|mut ix| {
                for meta in &mut ix.accounts {
                    if meta.pubkey == *nonce_authority {
                        meta.pubkey = acting;
                    }
                }
                ix
            })
            .collect();
        let passthrough = (!instructions.is_empty()).then(|| {
            create_multi_passthrough_instruction(
                &[
                    PassthroughSigner::system(&ED25519, nonce_authority.as_ref()),
                    PassthroughSigner::vector(&ED25519, nonce_authority.as_ref()),
                ],
                &instructions,
            )
        });
        Self {
            authority: *nonce_authority,
            nonce_account: *nonce_account,
            fee_payer: payer.copied(),
            passthrough,
        }
    }

    fn signer(&self) -> AdvanceSigner<'_> {
        AdvanceSigner {
            nonce_account: Some(self.nonce_account),
            ..AdvanceSigner::new(&ED25519, self.authority.as_ref())
        }
    }

    fn post(&self) -> &[Instruction] {
        self.passthrough.as_slice()
    }

    /// What the authority signs over `nonce`, the nonce account's
    /// [`Data::blockhash`]. It is also the nonce account's next nonce.
    pub fn digest(&self, nonce: &Hash) -> [u8; 32] {
        let message = advance_message(&[self.signer()], &[], self.post(), self.fee_payer.as_ref());
        signer_digest(&message, nonce.as_bytes(), &vector(&self.authority), &[])
    }

    /// Sign over `nonce` with the nonce authority, offline.
    pub fn sign(&self, nonce: &Hash, authority: &dyn Signer) -> Result<Signature, SignerError> {
        if authority.try_pubkey()? != self.authority {
            return Err(SignerError::KeypairPubkeyMismatch);
        }
        authority.try_sign_message(&self.digest(nonce))
    }

    /// Check `signature` over `nonce` as the program will, offline.
    pub fn verify(&self, nonce: &Hash, signature: &Signature) -> Result<(), Error> {
        verify_advance_signature(
            self.signer(),
            nonce.as_bytes(),
            &[],
            self.post(),
            self.fee_payer.as_ref(),
            signature.as_ref(),
        )
        .map(drop)
        .map_err(|_| Error::InvalidSignature)
    }

    /// The transaction carrying the message, with the authority's
    /// `signature` in its `Advance`.
    fn transaction(&self, signature: &Signature) -> Transaction {
        let advance = create_multi_advance_instruction(&[(self.signer(), signature.as_ref())]);
        let instructions: Vec<_> = core::iter::once(advance)
            .chain(self.passthrough.clone())
            .collect();
        Transaction::new_unsigned(Message::new(&instructions, self.fee_payer.as_ref()))
    }
}

/// A transaction carrying a [`NoncedMessage`], the `Transaction` of durable
/// nonces. The nonce authority signs over the nonce, offline; the fee payer
/// and any other signer sign over a recent blockhash, when it is submitted.
///
/// It serializes as the `Transaction` it carries, so whoever submits it
/// deserializes a `Transaction` and signs it as any other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoncedTransaction {
    message: NoncedMessage,
    transaction: Transaction,
}

impl NoncedTransaction {
    /// `Transaction::new_unsigned`.
    pub fn new_unsigned(message: NoncedMessage) -> Self {
        let transaction = message.transaction(&Signature::default());
        Self {
            message,
            transaction,
        }
    }

    /// `Transaction::try_partial_sign`. The nonce authority signs alone,
    /// with `hash` the nonce, and first: its signature changes the
    /// transaction. The others sign with `hash` a recent blockhash.
    pub fn try_partial_sign<T: Signers + ?Sized>(
        &mut self,
        signers: &T,
        hash: Hash,
    ) -> Result<(), SignerError> {
        let pubkeys = signers.try_pubkeys()?;
        if !pubkeys.contains(&self.message.authority) {
            return self.transaction.try_partial_sign(signers, hash);
        }
        let [_] = pubkeys[..] else {
            return Err(SignerError::Custom(
                "the nonce authority signs alone: over the nonce, the others over a recent blockhash"
                    .into(),
            ));
        };
        let [signature] = signers.try_sign_message(&self.message.digest(&hash))?[..] else {
            unreachable!("one signer, one signature");
        };
        self.transaction = self.message.transaction(&signature);
        Ok(())
    }

    /// The transaction to submit.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
}

impl From<NoncedTransaction> for Transaction {
    fn from(transaction: NoncedTransaction) -> Self {
        transaction.transaction
    }
}

impl Serialize for NoncedTransaction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.transaction.serialize(serializer)
    }
}
