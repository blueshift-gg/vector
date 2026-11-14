//! `fixtures/vectors.json`: one `Advance` signed by every scheme, Ed25519 over
//! a nonce account, with a `Passthrough` and an expiry, as reference
//! signers made it. The TypeScript tests rebuild the same bytes from the same
//! file, so the two SDKs cannot drift apart or from the program.
//!
//! Signing is randomized for some schemes, so the file is written once by
//! `regenerate_vectors` and then checked: every byte that follows from the
//! keys is rebuilt and compared, and every signature is verified.

use ed25519_dalek::{Signer as _, SigningKey};
use fips204::{
    ml_dsa_44,
    traits::{KeyGen, SerDes, Signer as _},
};
use k256::ecdsa::{Signature as Secp256k1Signature, SigningKey as Secp256k1SigningKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use serde_json::{json, Value};
use solana_address::Address;
use solana_instruction::Instruction;
use solana_winternitz::hazmat;
use vector_signer::{
    advance_message, advance_vector_digest, create_multi_advance_instruction,
    create_passthrough_instruction, create_withdraw_subinstruction, ed25519_pubkey,
    eip191_envelope_hash, find_system_pda, find_vector_pda, rotating_advance_vector_digest,
    secp256k1_compressed_pubkey, secp256k1_eip191_eth_address, signed, signed_nonce, signer_digest,
    vector_seed, verify_advance, AdvanceEntry, AdvanceSigner, Scheme, SignerNonce, ED25519, EIP191,
    FALCON512, MLDSA44, SECP256K1, WINTERNITZ, XMSS,
};

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixtures/vectors.json");
const VALID_UNTIL: u64 = 1_234_567;
const SCHEMES: [Scheme; 7] = [
    ED25519, EIP191, SECP256K1, FALCON512, MLDSA44, WINTERNITZ, XMSS,
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(value: &Value) -> Vec<u8> {
    let s = value.as_str().unwrap();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn address(value: &Value) -> Address {
    value.as_str().unwrap().parse().unwrap()
}

fn instruction_json(instruction: &Instruction) -> Value {
    json!({
        "programId": instruction.program_id.to_string(),
        "keys": instruction.accounts.iter().map(|meta| json!({
            "pubkey": meta.pubkey.to_string(),
            "isSigner": meta.is_signer,
            "isWritable": meta.is_writable,
        })).collect::<Vec<_>>(),
        "data": hex(&instruction.data),
    })
}

/// Everything about one signer that follows from its key and nonce.
struct Signer {
    scheme: Scheme,
    identity: Vec<u8>,
    nonce: [u8; 32],
    next_key: Vec<u8>,
}

/// The accounts, the `Passthrough` and the nonces every vector shares.
struct Setup {
    /// The fee payer is also the withdrawal's receiver, so the message
    /// covers the flags the runtime gives it.
    fee_payer: Address,
    nonce_account: Address,
    nonce_account_nonce: [u8; 32],
}

impl Setup {
    fn new() -> Self {
        Self {
            fee_payer: Address::new_from_array([0x0f; 32]),
            nonce_account: Address::new_from_array([0x0e; 32]),
            nonce_account_nonce: [0xee; 32],
        }
    }

    fn passthrough(&self, ed25519: &[u8]) -> Instruction {
        create_passthrough_instruction(
            &ED25519,
            ed25519,
            &[create_withdraw_subinstruction(
                &ED25519,
                ed25519,
                &self.fee_payer,
                1_000,
            )],
        )
    }

    fn advance_signers<'a>(&self, signers: &'a [Signer]) -> Vec<AdvanceSigner<'a>> {
        signers
            .iter()
            .map(|signer| AdvanceSigner {
                nonce_account: (signer.scheme.id == ED25519.id).then_some(self.nonce_account),
                next_key: &signer.next_key,
                ..AdvanceSigner::new(&signer.scheme, &signer.identity)
            })
            .collect()
    }

    /// What each signer signs over: its own nonce, or for Ed25519 its nonce
    /// account's with its own.
    fn signed_over(&self, signer: &Signer) -> [u8; 32] {
        match signer.scheme.id == ED25519.id {
            true => signed_nonce(&self.nonce_account_nonce, &signer.nonce),
            false => signer.nonce,
        }
    }

    /// The message, and each signer's digest in this advance and alone.
    fn digests(&self, signers: &[Signer]) -> ([u8; 32], Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let post = [self.passthrough(&signers[0].identity)];
        let message = advance_message(
            VALID_UNTIL,
            &self.advance_signers(signers),
            &[],
            &post,
            Some(&self.fee_payer),
        );
        let digests = signers
            .iter()
            .map(|signer| {
                let vector = find_vector_pda(&signer.scheme, &signer.identity).0;
                signer_digest(
                    &message,
                    &self.signed_over(signer),
                    &vector,
                    &signer.next_key,
                )
            })
            .collect();
        let alone = signers
            .iter()
            .map(|signer| match signer.scheme.next_key_len {
                0 => advance_vector_digest(
                    &signer.scheme,
                    &signer.nonce,
                    &signer.identity,
                    &[],
                    &post,
                    Some(&self.fee_payer),
                ),
                _ => rotating_advance_vector_digest(
                    &signer.scheme,
                    &signer.nonce,
                    &signer.identity,
                    &signer.next_key,
                    &[],
                    &post,
                    Some(&self.fee_payer),
                ),
            })
            .collect();
        (message, digests, alone)
    }

    fn json(&self, signers: &[Signer], signatures: &[Vec<u8>]) -> Value {
        let (message, digests, alone) = self.digests(signers);
        let entries: Vec<_> = self
            .advance_signers(signers)
            .into_iter()
            .zip(signatures)
            .map(|(signer, signature)| (signer, &signature[..]))
            .collect();
        let advance = create_multi_advance_instruction(VALID_UNTIL, &entries);
        json!({
            "validUntil": VALID_UNTIL.to_string(),
            "feePayer": self.fee_payer.to_string(),
            "nonceAccount": self.nonce_account.to_string(),
            "nonceAccountNonce": hex(&self.nonce_account_nonce),
            "passthrough": instruction_json(&self.passthrough(&signers[0].identity)),
            "advance": instruction_json(&advance),
            "message": hex(&message),
            "signers": signers.iter().enumerate().map(|(i, signer)| {
                let (vector, bump) = find_vector_pda(&signer.scheme, &signer.identity);
                json!({
                    "scheme": signer.scheme.id,
                    "identity": hex(&signer.identity),
                    "vector": vector.to_string(),
                    "bump": bump,
                    "seed": hex(&vector_seed(&signer.identity)),
                    "systemPda": find_system_pda(&vector).0.to_string(),
                    "nonce": hex(&signer.nonce),
                    "nextKey": hex(&signer.next_key),
                    "signedOver": hex(&self.signed_over(signer)),
                    "digest": hex(&digests[i]),
                    "aloneDigest": hex(&alone[i]),
                    "signature": hex(&signatures[i]),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Fills with a fixed stream: these keys are for tests only.
fn fill(
    state: &mut u64,
) -> impl FnMut(&mut [u8]) -> Result<(), solana_winternitz::SigningError> + '_ {
    crate::rotation::fill(state)
}

#[test]
#[ignore = "writes fixtures/vectors.json; run when the format changes"]
fn regenerate_vectors() {
    let ed25519 = SigningKey::from_bytes(&[1; 32]);
    let secp256k1 = Secp256k1SigningKey::from_slice(&[2; 32]).unwrap();
    let eip191 = Secp256k1SigningKey::from_slice(&[3; 32]).unwrap();
    let (falcon_pk, falcon_sk) = falcon512::keypair();
    let (mldsa_pk, mldsa_sk) = ml_dsa_44::KG::try_keygen().unwrap();
    let mut state = 11;
    let winternitz = hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let winternitz_next = hazmat::SecretKey::generate(fill(&mut state)).unwrap();
    let xmss = solana_xmss::hazmat::SecretKey::generate(fill(&mut state)).unwrap();

    let identities: [Vec<u8>; 7] = [
        ed25519_pubkey(&ed25519).to_vec(),
        secp256k1_eip191_eth_address(&eip191).to_vec(),
        secp256k1_compressed_pubkey(&secp256k1).to_vec(),
        falcon_pk.as_bytes().to_vec(),
        mldsa_pk.into_bytes().to_vec(),
        winternitz.verifying_key().to_bytes().to_vec(),
        xmss.verifying_key().to_bytes().to_vec(),
    ];
    let next_keys: [Vec<u8>; 7] = [
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        winternitz_next.verifying_key().to_bytes().to_vec(),
        // XMSS keeps its key.
        identities[6].clone(),
    ];
    let signers: Vec<Signer> = SCHEMES
        .iter()
        .zip(identities)
        .zip(next_keys)
        .enumerate()
        .map(|(i, ((scheme, identity), next_key))| Signer {
            scheme: *scheme,
            identity,
            nonce: [0x10 + i as u8; 32],
            next_key,
        })
        .collect();

    let setup = Setup::new();
    let (_, digests, _) = setup.digests(&signers);
    let signatures = vec![
        ed25519.sign(&signed(&digests[0])).to_bytes().to_vec(),
        {
            let (signature, recovery) = eip191
                .sign_prehash_recoverable(&eip191_envelope_hash(&digests[1]))
                .unwrap();
            [&signature.to_bytes()[..], &[recovery.to_byte()]].concat()
        },
        {
            let signature: Secp256k1Signature =
                k256::ecdsa::signature::hazmat::PrehashSigner::sign_prehash(
                    &secp256k1,
                    &crate::common::signed_hash_ecdsa(&digests[2]),
                )
                .unwrap();
            signature.to_bytes().to_vec()
        },
        {
            let mut wire = falcon512::detached_sign(&signed(&digests[3]), &falcon_sk)
                .as_bytes()
                .to_vec();
            wire.resize(FALCON512.signature_len, 0);
            wire
        },
        mldsa_sk
            .try_sign(&signed(&digests[4]), &[])
            .unwrap()
            .to_vec(),
        winternitz
            .sign_at(
                0,
                &crate::common::signed_hash(&digests[5]),
                fill(&mut state),
            )
            .unwrap()
            .as_bytes()
            .to_vec(),
        // A leaf past 0, so the leaf field is not all zeros.
        xmss.sign_at(
            5,
            &crate::common::signed_hash(&digests[6]),
            fill(&mut state),
        )
        .unwrap()
        .as_bytes()
        .to_vec(),
    ];
    let json = setup.json(&signers, &signatures);
    std::fs::write(FILE, serde_json::to_string_pretty(&json).unwrap() + "\n").unwrap();
}

#[test]
fn vectors_are_what_the_program_and_sdk_compute() {
    let fixture: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    assert_eq!(fixture["validUntil"], VALID_UNTIL.to_string());
    let setup = Setup::new();
    assert_eq!(address(&fixture["feePayer"]), setup.fee_payer);
    assert_eq!(address(&fixture["nonceAccount"]), setup.nonce_account);
    assert_eq!(
        unhex(&fixture["nonceAccountNonce"]),
        setup.nonce_account_nonce
    );

    let listed = fixture["signers"].as_array().unwrap();
    assert_eq!(listed.len(), SCHEMES.len());
    let signers: Vec<Signer> = listed
        .iter()
        .zip(SCHEMES)
        .map(|(signer, scheme)| {
            assert_eq!(signer["scheme"], scheme.id);
            Signer {
                scheme,
                identity: unhex(&signer["identity"]),
                nonce: unhex(&signer["nonce"]).try_into().unwrap(),
                next_key: unhex(&signer["nextKey"]),
            }
        })
        .collect();
    let signatures: Vec<Vec<u8>> = listed
        .iter()
        .map(|signer| unhex(&signer["signature"]))
        .collect();

    // Every byte that follows from the keys, nonces and signatures.
    assert_eq!(setup.json(&signers, &signatures), fixture);

    // And every signature verifies, with the program's own code.
    let advance_signers = setup.advance_signers(&signers);
    let entries: Vec<AdvanceEntry> = advance_signers
        .iter()
        .zip(&signers)
        .zip(&signatures)
        .map(|((&signer, of), signature)| {
            AdvanceEntry::new(
                signer,
                SignerNonce::Signed(setup.signed_over(of)),
                signature,
            )
        })
        .collect();
    let digests = verify_advance(
        VALID_UNTIL,
        &entries,
        &[],
        &[setup.passthrough(&signers[0].identity)],
        Some(&setup.fee_payer),
        Some(VALID_UNTIL),
    )
    .unwrap();
    assert_eq!(digests, setup.digests(&signers).1);

    // A signature moved to another signer's place does not verify.
    let mut swapped = entries.clone();
    swapped[2].signature = entries[0].signature;
    assert!(verify_advance(
        VALID_UNTIL,
        &swapped,
        &[],
        &[setup.passthrough(&signers[0].identity)],
        Some(&setup.fee_payer),
        None,
    )
    .is_err());
}
