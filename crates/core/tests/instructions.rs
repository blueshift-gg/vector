use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use vector_core::{create_passthrough_instruction, find_vector_pda, ED25519};

#[test]
fn passthrough_preserves_external_signers() {
    let identity = [7; 32];
    let (pda, _) = find_vector_pda(&ED25519, &identity);
    let cosigner = Address::new_unique();
    let nested = Instruction {
        program_id: Address::new_unique(),
        accounts: vec![
            AccountMeta::new_readonly(pda, true),
            AccountMeta::new(cosigner, true),
        ],
        data: vec![],
    };
    let outer = create_passthrough_instruction(&ED25519, &identity, std::slice::from_ref(&nested));
    assert_eq!(
        &outer.accounts[3..],
        &[
            AccountMeta::new_readonly(pda, false),
            AccountMeta::new(cosigner, true),
        ]
    );
    assert!(nested.accounts.iter().all(|meta| meta.is_signer));
}
