//! `blueshift-nonce`: the `solana` CLI's durable nonce commands, for nonce
//! accounts that outlive durable nonces. Same names, arguments and
//! `--sign-only` / `--signer` flow; it reads `solana config`.

use std::{error::Error, str::FromStr};

use blueshift_nonce::{
    close_nonce_account, create_nonce_account, data_from_account, system_account, vector, Data,
    Error as NonceError, NoncedMessage, NoncedTransaction,
};
use clap::{Args, Parser, Subcommand};
use solana_cli_config::{normalize_to_url_if_moniker, Config, CONFIG_FILE};
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_keypair::{read_keypair_file, Keypair};
use solana_native_token::sol_str_to_lamports;
use solana_presigner::Presigner;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use solana_transaction::Transaction;
use vector_core::{create_initialize_instruction, ED25519};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// JSON RPC URL or moniker [default: from `solana config`]
    #[arg(short, long, global = true)]
    url: Option<String>,
    /// Default fee payer and nonce authority [default: from `solana config`]
    #[arg(short, long, global = true)]
    keypair: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The address that takes AUTHORITY's place: move its SOL, tokens and
    /// authorities there, once
    Address {
        /// Pubkey or keypair [default: the fee payer]
        authority: Option<String>,
    },
    /// Create a nonce account, and the authority's vector if it has none
    CreateNonceAccount {
        nonce_account_keypair: String,
        /// SOL to fund it with, at least rent for 64 bytes
        #[arg(value_parser = sol)]
        amount: u64,
        /// [default: the fee payer]
        #[arg(long)]
        nonce_authority: Option<Pubkey>,
    },
    /// Print the nonce, what the next message over the account signs over
    #[command(visible_alias = "nonce-account", alias = "get-nonce")]
    Nonce { nonce_account: Pubkey },
    /// Move the nonce, cancelling every message signed over it
    NewNonce {
        nonce_account: Pubkey,
        #[command(flatten)]
        signing: Signing,
    },
    /// Close a nonce account, sending its SOL to RECIPIENT
    #[command(alias = "withdraw-from-nonce-account")]
    CloseNonceAccount {
        nonce_account: Pubkey,
        recipient: Pubkey,
        #[command(flatten)]
        signing: Signing,
    },
    /// Send SOL from the nonce authority's system account
    Transfer {
        recipient: Pubkey,
        #[arg(value_parser = sol)]
        amount: u64,
        /// The nonce account to sign over
        #[arg(long)]
        nonce: Pubkey,
        #[command(flatten)]
        signing: Signing,
    },
}

#[derive(Args)]
struct Signing {
    /// Keypair, or pubkey with --signer [default: --keypair]
    #[arg(long)]
    nonce_authority: Option<String>,
    /// Keypair, or pubkey with --sign-only [default: --keypair]
    #[arg(long)]
    fee_payer: Option<String>,
    /// Sign, print the signature and stop; submit later with --signer
    #[arg(long)]
    sign_only: bool,
    /// The nonce to sign over, to sign without RPC
    #[arg(long)]
    blockhash: Option<Hash>,
    /// PUBKEY=SIGNATURE, printed by --sign-only
    #[arg(long, value_parser = presigner)]
    signer: Vec<(Pubkey, Signature)>,
}

struct Context {
    rpc: RpcClient,
    keypair: String,
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result {
    let config = CONFIG_FILE
        .as_ref()
        .and_then(|file| Config::load(file).ok())
        .unwrap_or_default();
    let url = normalize_to_url_if_moniker(cli.url.unwrap_or(config.json_rpc_url));
    let commitment = CommitmentConfig::from_str(&config.commitment).unwrap_or_default();
    let context = Context {
        rpc: RpcClient::new_with_commitment(url, commitment),
        keypair: cli.keypair.unwrap_or(config.keypair_path),
    };

    match cli.command {
        Command::Address { authority } => {
            let (authority, _) = context.signer(authority.as_deref())?;
            println!("{}", system_account(&authority));
        }
        Command::CreateNonceAccount {
            nonce_account_keypair,
            amount,
            nonce_authority,
        } => {
            let payer = context.payer()?;
            let nonce = read_keypair_file(&nonce_account_keypair)?;
            let authority = nonce_authority.unwrap_or(payer.pubkey());
            let mut instructions = Vec::new();
            let exists = context
                .rpc
                .get_account_with_commitment(&vector(&authority), context.rpc.commitment())?
                .value
                .is_some();
            if !exists {
                instructions.push(create_initialize_instruction(
                    &payer.pubkey(),
                    &ED25519,
                    authority.as_ref(),
                ));
            }
            instructions.extend(create_nonce_account(
                &payer.pubkey(),
                &nonce.pubkey(),
                &authority,
                amount,
            ));
            context.send(&instructions, &[&payer, &nonce])?;
        }
        Command::Nonce { nonce_account } => {
            println!("{}", context.data(&nonce_account)?.blockhash());
        }
        Command::NewNonce {
            nonce_account,
            signing,
        } => context.signed(&nonce_account, signing, |_| Vec::new())?,
        Command::CloseNonceAccount {
            nonce_account,
            recipient,
            signing,
        } => context.signed(&nonce_account, signing, |authority| {
            vec![close_nonce_account(&nonce_account, authority, &recipient)]
        })?,
        Command::Transfer {
            recipient,
            amount,
            nonce,
            signing,
        } => context.signed(&nonce, signing, |authority| {
            vec![transfer(authority, &recipient, amount)]
        })?,
    }
    Ok(())
}

impl Context {
    fn payer(&self) -> Result<Keypair> {
        read_keypair_file(&self.keypair)
            .map_err(|error| format!("fee payer keypair {}: {error}", self.keypair).into())
    }

    /// A pubkey, or a keypair that signs as it; `--keypair` if none.
    fn signer(&self, arg: Option<&str>) -> Result<(Pubkey, Option<Keypair>)> {
        let keypair = match arg {
            Some(arg) => match Pubkey::from_str(arg) {
                Ok(pubkey) => return Ok((pubkey, None)),
                Err(_) => read_keypair_file(arg)?,
            },
            None => self.payer()?,
        };
        Ok((keypair.pubkey(), Some(keypair)))
    }

    fn data(&self, nonce_account: &Pubkey) -> Result<Data> {
        let account = self.rpc.get_account(nonce_account)?;
        let vector = account
            .data
            .get(32..64)
            .and_then(|vector| Pubkey::try_from(vector).ok())
            .ok_or(NonceError::UnexpectedDataSize)?;
        Ok(data_from_account(
            &account,
            &self.rpc.get_account(&vector)?,
        )?)
    }

    /// Sign `instructions` over `nonce_account` with the nonce authority, or
    /// take its `--signer` signature, then print it or submit.
    fn signed(
        &self,
        nonce_account: &Pubkey,
        signing: Signing,
        instructions: impl FnOnce(&Pubkey) -> Vec<Instruction>,
    ) -> Result {
        let (authority, keypair) = self.signer(signing.nonce_authority.as_deref())?;
        let (fee_payer, payer) = self.signer(signing.fee_payer.as_deref())?;
        let message = NoncedMessage::new_with_nonce(
            instructions(&authority),
            Some(&fee_payer),
            nonce_account,
            &authority,
        );
        let nonce = match signing.blockhash {
            Some(nonce) => nonce,
            None => {
                let data = self.data(nonce_account)?;
                if !data.is_authority(&authority) {
                    return Err(NonceError::InvalidAuthority {
                        provided: authority,
                        vector: data.vector,
                    }
                    .into());
                }
                data.durable_nonce
            }
        };
        let signature = match signing.signer.iter().find(|(key, _)| *key == authority) {
            Some(&(_, signature)) => signature,
            None => message.sign(
                &nonce,
                keypair
                    .as_ref()
                    .ok_or("the nonce authority is a pubkey: pass its --signer, or a keypair")?,
            )?,
        };

        if signing.sign_only {
            println!(
                "\nBlockhash: {nonce}\nSigners (Pubkey=Signature):\n  {authority}={signature}\n"
            );
            return Ok(());
        }
        // As `solana` does: the presigner checks the signature over the nonce.
        let mut transaction = NoncedTransaction::new_unsigned(message);
        transaction
            .try_partial_sign(&[&Presigner::new(&authority, &signature)], nonce)
            .map_err(|_| NonceError::InvalidSignature)?;
        let payer = payer.ok_or("the fee payer is a pubkey: pass its keypair to submit")?;
        transaction.try_partial_sign(&[&payer], self.rpc.get_latest_blockhash()?)?;
        println!(
            "Signature: {}",
            self.rpc
                .send_and_confirm_transaction(transaction.transaction())?
        );
        Ok(())
    }

    fn send(&self, instructions: &[Instruction], signers: &[&Keypair]) -> Result {
        let transaction = Transaction::new_signed_with_payer(
            instructions,
            Some(&signers[0].pubkey()),
            signers,
            self.rpc.get_latest_blockhash()?,
        );
        println!(
            "Signature: {}",
            self.rpc.send_and_confirm_transaction(&transaction)?
        );
        Ok(())
    }
}

fn sol(amount: &str) -> std::result::Result<u64, String> {
    sol_str_to_lamports(amount).ok_or_else(|| format!("{amount} is not an amount of SOL"))
}

fn presigner(arg: &str) -> std::result::Result<(Pubkey, Signature), String> {
    let (pubkey, signature) = arg.split_once('=').ok_or("expected PUBKEY=SIGNATURE")?;
    Ok((
        pubkey
            .parse()
            .map_err(|_| format!("{pubkey} is not a pubkey"))?,
        signature
            .parse()
            .map_err(|_| format!("{signature} is not a signature"))?,
    ))
}
