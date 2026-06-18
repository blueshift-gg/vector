//! The transportable [`Artifact`] and the [`Op`] an authorization runs.
use solana_address::Address;
use solana_instruction::Instruction;

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
