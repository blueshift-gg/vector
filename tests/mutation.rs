//! Randomized hardening: one valid transaction, an Ed25519 signer over a
//! nonce account and an XMSS signer, then a `Passthrough` withdrawal. Every
//! change to its instruction data or accounts must fail and leave every
//! account as it was. The signatures are made once; no key signs twice.

use std::collections::BTreeMap;

use blueshift_vector::{
    advance_message, create_multi_advance_instruction, create_passthrough_instruction,
    create_withdraw_subinstruction, ed25519_pubkey, find_vector_pda, signed, signed_nonce,
    signer_digest, AdvanceSigner, ED25519, NEVER_EXPIRES, PROGRAM_ID, XMSS,
};
use ed25519_dalek::{Signer, SigningKey};
use mollusk_svm::{result::types::TransactionProgramResult, Mollusk};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_xmss::hazmat::SecretKey;

use crate::common::{build_vector_account, mollusk, process_transaction, xmss_stored, NONCE};

const ITERATIONS: usize = 1_500;
const FUNDS: u64 = 10_000_000_000;
const FIRST: [u8; 32] = [0x11; 32];

/// A fixed stream, so a failure reproduces.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn at(slot: u64) -> Mollusk {
    let mut mollusk = mollusk();
    mollusk.warp_to_slot(slot);
    mollusk
}

#[test]
fn any_change_to_a_signed_transaction_fails_and_changes_nothing() {
    let ed25519 = SigningKey::from_bytes(&[3; 32]);
    let alice = ed25519_pubkey(&ed25519);
    let (alice_vector, _) = find_vector_pda(&ED25519, &alice);
    let nonce = Address::new_from_array([0x42; 32]);

    let mut state = 7;
    let xmss = SecretKey::generate(crate::rotation::fill(&mut state)).unwrap();
    let bob = xmss.verifying_key().to_bytes();
    let (bob_vector, _) = find_vector_pda(&XMSS, &bob);

    let receiver = Address::new_unique();
    // Named by no instruction, as signed.
    let stranger = Address::new_unique();
    let accounts = vec![
        (
            alice_vector,
            build_vector_account(NONCE, &ED25519, &alice, FUNDS, &alice),
        ),
        (receiver, Account::new(1_000_000, 0, &Address::default())),
        (
            nonce,
            Account {
                lamports: 1_500_000,
                data: [&FIRST[..], alice_vector.as_ref(), &0u64.to_le_bytes()].concat(),
                owner: PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        ),
        (
            bob_vector,
            build_vector_account(NONCE, &XMSS, &bob, FUNDS, &xmss_stored(&bob, 0)),
        ),
        (stranger, Account::new(1_000_000, 0, &Address::default())),
    ];

    let passthrough = create_passthrough_instruction(
        &ED25519,
        &alice,
        &[create_withdraw_subinstruction(
            &ED25519, &alice, &receiver, 1_000,
        )],
    );
    let signers = [
        AdvanceSigner {
            nonce_account: Some(nonce),
            ..AdvanceSigner::new(&ED25519, &alice)
        },
        // Bob keeps his key.
        AdvanceSigner {
            next_key: &bob,
            ..AdvanceSigner::new(&XMSS, &bob)
        },
    ];
    let message = advance_message(
        NEVER_EXPIRES,
        &signers,
        &[],
        std::slice::from_ref(&passthrough),
        None,
    );
    let alice_digest = signer_digest(&message, &signed_nonce(&FIRST, &NONCE), &alice_vector, &[]);
    let alice_signature = ed25519.sign(&signed(&alice_digest)).to_bytes();
    let bob_digest = signer_digest(&message, &NONCE, &bob_vector, &bob);
    let bob_signature = xmss
        .sign_at(
            0,
            &crate::common::signed_hash(&bob_digest),
            crate::rotation::fill(&mut state),
        )
        .unwrap();
    let advance = create_multi_advance_instruction(
        NEVER_EXPIRES,
        &[
            (signers[0], &alice_signature[..]),
            (signers[1], bob_signature.as_bytes()),
        ],
    );
    let transaction = [advance, passthrough];

    let mollusk = at(1);
    let run = |transaction: &[Instruction]| {
        process_transaction(
            &mollusk,
            &transaction.iter().collect::<Vec<_>>(),
            &accounts,
            &[],
        )
    };

    // As signed, it lands.
    let result = run(&transaction);
    assert_eq!(result.program_result, TransactionProgramResult::Success);
    assert_eq!(
        result.resulting_accounts[2].1.data[..32],
        alice_digest,
        "the nonce account moves to Alice's digest"
    );
    assert_eq!(
        result.resulting_accounts[3].1.data[..32],
        bob_digest,
        "Bob's vector moves to his digest"
    );

    let keys: Vec<Address> = accounts.iter().map(|(key, _)| *key).collect();
    let mut rng = Rng(0x5eed);
    let mut errors = BTreeMap::<String, usize>::new();
    let mut tried = 0;
    while tried < ITERATIONS {
        let mut changed = transaction.clone();
        let instruction = &mut changed[rng.below(2)];
        match rng.below(6) {
            // Flip one bit of the data.
            0 => {
                let at = rng.below(instruction.data.len());
                instruction.data[at] ^= 1 << rng.below(8);
            }
            // Cut the data short.
            1 => {
                let len = rng.below(instruction.data.len());
                instruction.data.truncate(len);
            }
            // One byte more, at the end.
            2 => instruction.data.push(rng.next() as u8),
            // One byte more, anywhere.
            3 => {
                let at = rng.below(instruction.data.len() + 1);
                instruction.data.insert(at, rng.next() as u8);
            }
            // Another account in one place.
            4 => {
                let at = rng.below(instruction.accounts.len());
                instruction.accounts[at].pubkey = keys[rng.below(keys.len())];
            }
            // Two accounts swapped. Two places naming one account are the
            // same account: the runtime gives it the same flags in both, so
            // swapping them changes nothing.
            _ => {
                let a = rng.below(instruction.accounts.len());
                let b = rng.below(instruction.accounts.len());
                if instruction.accounts[a].pubkey == instruction.accounts[b].pubkey {
                    continue;
                }
                instruction.accounts.swap(a, b);
            }
        }
        if changed == transaction {
            continue;
        }
        tried += 1;

        let result = run(&changed);
        let TransactionProgramResult::Failure(_, error) = &result.program_result else {
            let diff: Vec<_> = transaction
                .iter()
                .zip(&changed)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .map(|(i, (a, b))| {
                    let metas: Vec<_> = a
                        .accounts
                        .iter()
                        .zip(&b.accounts)
                        .enumerate()
                        .filter(|(_, (x, y))| x != y)
                        .map(|(j, (x, y))| format!("meta {j}: {} -> {}", x.pubkey, y.pubkey))
                        .collect();
                    let first = a.data.iter().zip(&b.data).position(|(x, y)| x != y);
                    format!(
                        "instruction {i}: data len {} -> {}, first differing byte {first:?}, {metas:?}",
                        a.data.len(),
                        b.data.len()
                    )
                })
                .collect();
            panic!("a changed transaction landed: {diff:#?}");
        };
        *errors.entry(format!("{error:?}")).or_default() += 1;
        for ((key, before), (_, after)) in accounts.iter().zip(&result.resulting_accounts) {
            assert_eq!(before, after, "{key} changed in a failed transaction");
        }
    }
    println!("{tried} changed transactions, all refused: {errors:#?}");
}
