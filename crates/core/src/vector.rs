//! The transportable [`Artifact`] and the [`Op`] an authorization runs.
use solana_address::Address;
use solana_instruction::Instruction;

use crate::instructions::{
    create_advance_instruction, create_close_subinstruction, create_passthrough_instruction,
    create_withdraw_subinstruction,
};
use crate::protocol::digest::advance_vector_digest;
use crate::protocol::pda::find_vector_pda;
use crate::scheme::{Registration, Signer, SingleTxRegister};

/// What an authorization executes: nothing (inert advance / revoke), one CPI,
/// or many — all run under the vector PDA's signer seeds.
#[derive(Clone, Debug)]
pub enum Op {
    /// No-op advance: rotate the nonce only (revoke / checkpoint).
    Inert,
    /// A single CPI instruction to run under the PDA's signer seeds.
    One(Instruction),
    /// Multiple CPI instructions to run sequentially under the PDA's signer seeds.
    Many(Vec<Instruction>),
}

impl Op {
    /// Flatten the op into a `Vec<Instruction>` (empty for `Inert`).
    pub fn into_vec(self) -> Vec<Instruction> {
        match self {
            Op::Inert => vec![],
            Op::One(i) => vec![i],
            Op::Many(v) => v,
        }
    }
}

impl From<Instruction> for Op {
    fn from(i: Instruction) -> Self {
        Op::One(i)
    }
}

impl From<Vec<Instruction>> for Op {
    fn from(v: Vec<Instruction>) -> Self {
        Op::Many(v)
    }
}

/// Front door for one signing identity. Generic over the scheme's `Signer`.
pub struct Vector<S: Signer> {
    signer: S,
    fee_payer: Option<Address>,
}

impl<S: Signer> Vector<S> {
    /// Create a `Vector` with no explicit fee payer (the runtime default will be used).
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            fee_payer: None,
        }
    }
    /// Create a `Vector` and record `fee_payer` in every emitted [`Artifact`].
    pub fn with_fee_payer(signer: S, fee_payer: Address) -> Self {
        Self {
            signer,
            fee_payer: Some(fee_payer),
        }
    }
    /// Client-side identity bytes for this signer (delegated to `S::identity`).
    pub fn identity(&self) -> Vec<u8> {
        self.signer.identity()
    }
    /// Derive the on-chain PDA address for this identity.
    pub fn pda(&self) -> Address {
        find_vector_pda(&S::descriptor(), &self.identity()).0
    }
}

impl<S: Registration> Vector<S> {
    /// Account-registration txs (one group per tx). Single-tx schemes return one group.
    pub fn register(&self, payer: &Address) -> Vec<Vec<Instruction>> {
        self.signer.registration_groups(payer)
    }

    /// Authorize an op against `nonce`: sign the advance digest, lay out
    /// `[..pre, advance, passthrough?]`. `Op::Inert` ⇒ advance only (revoke).
    pub fn authorize(&self, nonce: &[u8; 32], op: Op) -> Artifact {
        let identity = self.identity();
        let pre = self.signer.advance_pre_instructions();
        let ops = op.into_vec();
        let post: Vec<Instruction> = if ops.is_empty() {
            Vec::new()
        } else {
            vec![create_passthrough_instruction(
                &S::descriptor(),
                &identity,
                &ops,
            )]
        };
        let digest = advance_vector_digest(&S::descriptor(), nonce, &identity, &pre, &post);
        let sig = self.signer.sign(&digest);
        let advance = create_advance_instruction(&S::descriptor(), &identity, &sig);
        let advance_index = pre.len();
        let mut instructions = pre;
        instructions.push(advance);
        instructions.extend(post);
        Artifact {
            program_id: S::PROGRAM_ID,
            identity,
            nonce: *nonce,
            next_nonce: digest,
            fee_payer: self.fee_payer,
            public_key: self.signer.public_key(),
            advance_index,
            instructions,
        }
    }
    /// Ordered, forward-secure: each op is signed against the previous op's
    /// `next_nonce`, so step N can't land before step N-1.
    pub fn chain(&self, nonce: &[u8; 32], ops: &[Op]) -> Vec<Artifact> {
        let mut cur = *nonce;
        let mut out = Vec::with_capacity(ops.len());
        for op in ops {
            let art = self.authorize(&cur, op.clone());
            cur = art.next_nonce;
            out.push(art);
        }
        out
    }

    /// Mutually exclusive arms: every arm is signed against the same `nonce`;
    /// landing one advances the nonce and orphans the rest atomically.
    pub fn branch(
        &self,
        nonce: &[u8; 32],
        arms: std::collections::BTreeMap<String, Op>,
    ) -> std::collections::BTreeMap<String, Artifact> {
        arms.into_iter()
            .map(|(k, op)| (k, self.authorize(nonce, op)))
            .collect()
    }

    /// Authorize a `withdraw` sub-instruction: drain `lamports` from the PDA to `to`.
    pub fn withdraw(&self, nonce: &[u8; 32], to: &Address, lamports: u64) -> Artifact {
        let ix = create_withdraw_subinstruction(&S::descriptor(), &self.identity(), to, lamports);
        self.authorize(nonce, Op::One(ix))
    }
    /// Authorize a `close` sub-instruction: drain the entire PDA balance to `to`.
    pub fn close(&self, nonce: &[u8; 32], to: &Address) -> Artifact {
        let ix = create_close_subinstruction(&S::descriptor(), &self.identity(), to);
        self.authorize(nonce, Op::One(ix))
    }
}

impl<S: SingleTxRegister> Vector<S> {
    /// Convenience for single-tx schemes: the lone `initialize` instruction.
    /// Compile-time-guaranteed single group by the `SingleTxRegister` bound.
    pub fn initialize(&self, payer: &Address) -> Instruction {
        self.signer.registration_groups(payer).remove(0).remove(0)
    }
}

impl<S: crate::scheme::Derivable> Vector<S> {
    /// Independent sub-account: same API, its own deterministic key + PDA.
    pub fn derive(&self, index: u32) -> Vector<S> {
        Vector {
            signer: self.signer.derive(index),
            fee_payer: self.fee_payer,
        }
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod derive_tests {
    use super::*;
    use crate::schemes::ed25519::Ed25519;
    #[test]
    fn derived_subaccounts_are_deterministic_and_distinct() {
        let root = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        assert_eq!(root.derive(0).pda(), root.derive(0).pda()); // deterministic
        assert_ne!(root.derive(0).pda(), root.derive(1).pda()); // distinct
        assert_ne!(root.derive(0).pda(), root.pda()); // child != root
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod facade_tests {
    use super::*;
    use crate::scheme::SchemeMeta;
    use crate::schemes::ed25519::Ed25519;
    #[test]
    fn authorize_inert_is_advance_only() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let art = v.authorize(&[0u8; 32], Op::Inert);
        assert_eq!(art.program_id, Ed25519::PROGRAM_ID);
        assert_eq!(art.advance_index, 0);
        assert_eq!(art.instructions.len(), 1); // inert: advance only
        assert_ne!(art.next_nonce, [0u8; 32]);
    }
    #[test]
    fn authorize_with_op_appends_passthrough() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let to = Ed25519::PROGRAM_ID;
        let art = v.withdraw(&[0u8; 32], &to, 1);
        assert_eq!(art.instructions.len(), 2); // advance + passthrough
        assert_eq!(art.advance_index, 0);
    }
    #[test]
    fn register_single_group_for_curve() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let groups = v.register(&Ed25519::PROGRAM_ID);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 1);
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod branch_tests {
    use super::*;
    use crate::schemes::ed25519::Ed25519;
    #[test]
    fn chain_links_nonces() {
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let arts = v.chain(&[0u8; 32], &[Op::Inert, Op::Inert]);
        assert_eq!(arts.len(), 2);
        assert_eq!(arts[1].nonce, arts[0].next_nonce); // step 2 signed against step 1's result
        assert_ne!(arts[0].nonce, arts[1].nonce);
    }
    #[test]
    fn branches_share_nonce() {
        use std::collections::BTreeMap;
        let v = Vector::new(Ed25519::from_seed(&[1u8; 32]));
        let mut arms = BTreeMap::new();
        arms.insert("a".to_string(), Op::Inert);
        arms.insert("b".to_string(), Op::Inert);
        let out = v.branch(&[7u8; 32], arms);
        assert_eq!(out["a"].nonce, out["b"].nonce); // same source nonce
        assert_eq!(out.len(), 2);
    }
}

/// A signed, transportable authorization. `instructions` is the full ordered
/// layout `[..pre, advance, ..passthrough]`; `advance_index` is where the
/// advance sits.
#[derive(Clone, Debug, PartialEq)]
pub struct Artifact {
    /// Program ID of the scheme that produced this artifact.
    pub program_id: Address,
    /// Client-side identity bytes (pubkey or `sha256(wire_pk)` for PQ schemes).
    pub identity: Vec<u8>,
    /// Nonce the signer committed to; becomes stale once the advance lands.
    pub nonce: [u8; 32],
    /// The advance digest: becomes the new on-chain nonce after the advance lands.
    pub next_nonce: [u8; 32],
    /// Optional explicit fee payer; `None` means the runtime default.
    pub fee_payer: Option<Address>,
    /// Wire public key (PQ schemes only); `None` for curve schemes.
    pub public_key: Option<Vec<u8>>,
    /// Index of the `advance` instruction within `instructions`.
    pub advance_index: usize,
    /// Full ordered instruction layout: `[..pre, advance, ..passthrough]`.
    pub instructions: Vec<Instruction>,
}
