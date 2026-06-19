mod offline;
mod online;
mod scheme_arg;

use clap::{Parser, Subcommand};
use scheme_arg::SchemeArg;

#[derive(Parser)]
#[command(
    name = "vector",
    about = "Offline-signed Solana transactions that replace durable nonces"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode an artifact's intent (offline).
    Inspect { file: String },
    /// Human-readable sign-off block for an artifact (offline).
    Review { file: String },
    /// Verify an artifact's signature offline (exit 0 = valid).
    Verify { file: String },
    /// Read the current nonce of a vector PDA.
    Nonce {
        #[arg(long)]
        url: String,
        pda: String,
    },
    /// Sign + broadcast an advance (optionally with a withdraw op).
    Advance {
        #[arg(long)]
        url: String,
        #[arg(long)]
        keypair: String,
        #[arg(long)]
        signer_seed: String,
        #[arg(long, value_enum)]
        scheme: SchemeArg,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        lamports: Option<u64>,
    },
    /// Audit whether an old authority's holdings have migrated to a PDA.
    Scan {
        #[arg(long)]
        url: String,
        #[arg(long)]
        owner: String,
        #[arg(long)]
        pda: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result: Result<(), String> = dispatch(cli).await;
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn dispatch(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Inspect { file } => {
            offline::inspect(&file).map(|lines| lines.iter().for_each(|l| println!("{l}")))
        }
        Commands::Review { file } => offline::review(&file).map(|s| println!("{s}")),
        Commands::Verify { file } => match offline::verify(&file)? {
            true => {
                println!("OK");
                Ok(())
            }
            false => {
                eprintln!("INVALID");
                std::process::exit(1)
            }
        },
        Commands::Nonce { url, pda } => online::nonce(&url, &pda).await,
        Commands::Advance {
            url,
            keypair,
            signer_seed,
            scheme,
            to,
            lamports,
        } => online::advance(&url, &keypair, &signer_seed, scheme, to, lamports).await,
        Commands::Scan { url, owner, pda } => online::scan(&url, &owner, &pda).await,
    }
}
