#[cfg(test)]
mod tests {
    use {
        mollusk_svm::{Mollusk, program::keyed_account_for_system_program, result::Check},
        mollusk_svm_programs_token::token::{self, keyed_account},
        solana_account::Account,
        solana_address::Address,
        solana_program_option::COption,
        solana_program_pack::Pack,
        spl_token_interface::{
            instruction::{AuthorityType, mint_to, set_authority},
            state::{Account as TokenAccount, AccountState, Mint},
        },
        vector_core::{
            VECTOR_PROGRAM_ID, VectorAccount, advance_vector_digest,
            create_initialize_instruction, find_vector_pda, sign_advance_instruction,
            sign_close_instruction,
        },
    };

    pub const SIGNER_ADDRESS: Address =
        Address::from_str_const("6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt");
    pub const SIGNER_PRIVKEY: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];
    pub const SEED: [u8; 32] = [0xff; 32];

    #[test]
    fn initialize_vector_account() {
        let mollusk = Mollusk::new(&VECTOR_PROGRAM_ID, "../target/deploy/vector_program");

        let (system_program, system_program_account) = keyed_account_for_system_program();
        let (payer, payer_account) = (
            Address::new_unique(),
            Account::new(1_000_000_000, 0, &system_program),
        );
        let (vector, _bump) = find_vector_pda(&SIGNER_ADDRESS);
        let vector_account = Account::default();

        let init_ix = create_initialize_instruction(&payer, &SIGNER_ADDRESS);

        let accounts = vec![
            (payer, payer_account),
            (vector, vector_account),
            (system_program, system_program_account),
        ];

        // Seed is derived on-chain from address + SlotHashes; just check
        // success, owner, and account size.
        mollusk.process_and_validate_instruction(
            &init_ix,
            &accounts,
            &[
                Check::success(),
                Check::account(&vector)
                    .owner(&VECTOR_PROGRAM_ID)
                    .space(VectorAccount::LEN)
                    .build(),
            ],
        );
    }

    #[test]
    fn advance_vector_empty() {
        let mut mollusk = Mollusk::new(&VECTOR_PROGRAM_ID, "../target/deploy/vector_program");
        token::add_program(&mut mollusk);

        let (vector, bump) = find_vector_pda(&SIGNER_ADDRESS);
        let vector_account = Account {
            lamports: mollusk.sysvars.rent.minimum_balance(VectorAccount::LEN),
            data: VectorAccount {
                seed: SEED,
                address: SIGNER_ADDRESS,
                bump,
            }
            .to_bytes()
            .into(),
            owner: VECTOR_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        let advance_ix = sign_advance_instruction(
            &SIGNER_PRIVKEY.into(),
            &SEED,
            &[],
            &[],
            &[],
        );

        let next_seed = advance_vector_digest(
            &SEED,
            &SIGNER_ADDRESS,
            &[],
            &[],
            &[],
        );
        let expected_vector_data = VectorAccount {
            seed: next_seed,
            address: SIGNER_ADDRESS,
            bump,
        }
        .to_bytes();

        let accounts = vec![
            (vector, vector_account),
        ];

        let result = mollusk.process_and_validate_instruction_chain(
            &[
                (
                    &advance_ix,
                    &[
                        Check::success(),
                        Check::account(&vector).data(&expected_vector_data).build(),
                    ],
                ),
            ],
            &accounts,
        );
        println!("{} CUs", result.compute_units_consumed);
    }

    #[test]
    fn advance_round_trips_spl_mint_authority() {
        let mut mollusk = Mollusk::new(&VECTOR_PROGRAM_ID, "../target/deploy/vector_program");
        token::add_program(&mut mollusk);

        let (token_program, token_program_account) = keyed_account();

        let (eoa, eoa_account) = (
            Address::new_unique(),
            Account::new(1_0000_000_000, 0, &Address::default()),
        );

        let (vector, bump) = find_vector_pda(&SIGNER_ADDRESS);
        let vector_account = Account {
            lamports: mollusk.sysvars.rent.minimum_balance(VectorAccount::LEN),
            data: VectorAccount {
                seed: SEED,
                address: SIGNER_ADDRESS,
                bump,
            }
            .to_bytes()
            .into(),
            owner: VECTOR_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };

        let (mint, mint_account) = (
            Address::new_unique(),
            token::create_account_for_mint(Mint {
                mint_authority: COption::Some(vector),
                supply: 0,
                decimals: 6,
                is_initialized: true,
                freeze_authority: COption::None,
            }),
        );

        let (destination, destination_account) = (
            Address::new_unique(),
            token::create_account_for_token_account(TokenAccount {
                mint,
                owner: Address::new_unique(),
                amount: 0,
                delegate: COption::None,
                state: AccountState::Initialized,
                is_native: COption::None,
                delegated_amount: 0,
                close_authority: COption::None,
            }),
        );

        let pda_to_eoa_ix = set_authority(
            &token::ID,
            &mint,
            Some(&eoa),
            AuthorityType::MintTokens,
            &vector,
            &[],
        )
        .unwrap();

        let mint_to_ix = mint_to(&token::ID, &mint, &destination, &eoa, &[], 10_000).unwrap();

        let eoa_to_pda_ix = set_authority(
            &token::ID,
            &mint,
            Some(&vector),
            AuthorityType::MintTokens,
            &eoa,
            &[],
        )
        .unwrap();

        let advance_ix = sign_advance_instruction(
            &SIGNER_PRIVKEY.into(),
            &SEED,
            &[pda_to_eoa_ix.clone()],
            &[],
            &[mint_to_ix.clone(), eoa_to_pda_ix.clone()],
        );

        // Recompute the digest the SDK signed so we can assert the new seed.
        let next_seed = advance_vector_digest(
            &SEED,
            &SIGNER_ADDRESS,
            &[pda_to_eoa_ix],
            &[],
            &[mint_to_ix.clone(), eoa_to_pda_ix.clone()],
        );
        let expected_vector_data = VectorAccount {
            seed: next_seed,
            address: SIGNER_ADDRESS,
            bump,
        }
        .to_bytes();

        let accounts = vec![
            (vector, vector_account),
            (token_program, token_program_account),
            (mint, mint_account),
            (destination, destination_account),
            (eoa, eoa_account),
        ];

        let mut expected_mint_data = vec![0u8; Mint::LEN];
        Mint::pack(
            Mint {
                mint_authority: COption::Some(vector),
                supply: 10_000,
                decimals: 6,
                is_initialized: true,
                freeze_authority: COption::None,
            },
            &mut expected_mint_data,
        )
        .unwrap();

        let result = mollusk.process_and_validate_instruction_chain(
            &[
                (
                    &advance_ix,
                    &[
                        Check::success(),
                        Check::account(&vector).data(&expected_vector_data).build(),
                    ],
                ),
                (&mint_to_ix, &[Check::success()]),
                (
                    &eoa_to_pda_ix,
                    &[
                        Check::success(),
                        Check::account(&mint).data(&expected_mint_data).build(),
                    ],
                ),
            ],
            &accounts,
        );
        println!("{} CUs", result.compute_units_consumed);
    }

    #[test]
    fn close_vector_account() {
        let mollusk = Mollusk::new(&VECTOR_PROGRAM_ID, "../target/deploy/vector_program");

        let vector_lamports = mollusk.sysvars.rent.minimum_balance(VectorAccount::LEN);
        let (vector, bump) = find_vector_pda(&SIGNER_ADDRESS);

        let vector_account = Account {
            lamports: vector_lamports,
            data: VectorAccount {
                seed: SEED,
                address: SIGNER_ADDRESS,
                bump,
            }
            .to_bytes()
            .into(),
            owner: VECTOR_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };

        let eoa_starting_lamports = 1_0000_000_000u64;
        let (eoa, eoa_account) = (
            Address::new_unique(),
            Account::new(eoa_starting_lamports, 0, &Address::default()),
        );

        let close_ix = sign_close_instruction(
            &SIGNER_PRIVKEY.into(),
            &SEED,
            &eoa,
            &[],
            &[],
        );

        let accounts = vec![
            (vector, vector_account),
            (eoa, eoa_account),
        ];

        mollusk.process_and_validate_instruction_chain(
            &[
                (
                    &close_ix,
                    &[
                        Check::success(),
                        Check::account(&vector).lamports(0).build(),
                        Check::account(&eoa)
                            .lamports(eoa_starting_lamports + vector_lamports)
                            .build(),
                    ],
                ),
            ],
            &accounts,
        );
    }
}
