//! The transportable [`Artifact`] and the [`Op`] an authorization runs.
use solana_address::Address;
use solana_instruction::Instruction;

use crate::instructions::{
    create_advance_instruction, create_close_subinstruction, create_passthrough_instruction,
    create_withdraw_subinstruction,
};
use crate::protocol::digest::advance_vector_digest;
use crate::protocol::pda::find_vector_pda;
use crate::scheme::Signer;

/// What an authorization executes: nothing (inert advance / revoke), one CPI,
/// or many — all run under the vector PDA's signer seeds.
#[derive(Clone, Debug)]
pub enum Op {
    Inert,
    One(Instruction),
    Many(Vec<Instruction>),
}

impl Op {
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
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            fee_payer: None,
        }
    }
    pub fn with_fee_payer(signer: S, fee_payer: Address) -> Self {
        Self {
            signer,
            fee_payer: Some(fee_payer),
        }
    }
    pub fn identity(&self) -> Vec<u8> {
        self.signer.identity()
    }
    pub fn pda(&self) -> Address {
        find_vector_pda(&S::descriptor(), &self.identity()).0
    }

    /// Account-registration txs (one group per tx). Single-tx schemes return one group.
    pub fn register(&self, payer: &Address) -> Vec<Vec<Instruction>> {
        self.signer.registration_groups(payer)
    }
    /// Convenience for single-tx schemes; panics for multi-tx schemes (use `register`).
    pub fn initialize(&self, payer: &Address) -> Instruction {
        let mut g = self.signer.registration_groups(payer);
        assert!(
            g.len() == 1 && g[0].len() == 1,
            "multi-tx scheme: use register()"
        );
        g.remove(0).remove(0)
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
    pub fn withdraw(&self, nonce: &[u8; 32], to: &Address, lamports: u64) -> Artifact {
        let ix = create_withdraw_subinstruction(&S::descriptor(), &self.identity(), to, lamports);
        self.authorize(nonce, Op::One(ix))
    }
    pub fn close(&self, nonce: &[u8; 32], to: &Address) -> Artifact {
        let ix = create_close_subinstruction(&S::descriptor(), &self.identity(), to);
        self.authorize(nonce, Op::One(ix))
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

/// A signed, transportable authorization. `instructions` is the full ordered
/// layout `[..pre, advance, ..passthrough]`; `advance_index` is where the
/// advance sits.
#[derive(Clone, Debug, PartialEq)]
pub struct Artifact {
    pub program_id: Address,
    pub identity: Vec<u8>,
    pub nonce: [u8; 32],
    pub next_nonce: [u8; 32],
    pub fee_payer: Option<Address>,
    pub public_key: Option<Vec<u8>>,
    pub advance_index: usize,
    pub instructions: Vec<Instruction>,
}
