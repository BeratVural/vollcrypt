use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use vollcrypt_shield_witness::{WitnessNode, now_unix_ms};

#[derive(Debug, Parser)]
#[command(name = "vollcrypt-shield-witness", version)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        id: String,
    },
    TrustAgent {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        agent_public_key: PathBuf,
    },
    PairAgent {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        invitation: String,
    },
    Attest {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Status {
        #[arg(long)]
        state_dir: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Arguments::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    match arguments.command {
        Command::Init { state_dir, id } => {
            let node = WitnessNode::initialize(&state_dir, &id)?;
            println!("{}", serde_json::to_string_pretty(&node.status())?);
        }
        Command::TrustAgent {
            state_dir,
            agent_public_key,
        } => {
            let mut node = WitnessNode::load(&state_dir)?;
            let key_id = node.trust_agent_public_key(&std::fs::read(agent_public_key)?)?;
            println!("{}", hex::encode(key_id));
        }
        Command::PairAgent {
            state_dir,
            invitation,
        } => {
            let mut node = WitnessNode::load(&state_dir)?;
            let key_id = node.pair_agent(&invitation)?;
            println!("{}", hex::encode(key_id));
        }
        Command::Attest {
            state_dir,
            request,
            output,
        } => {
            let mut node = WitnessNode::load(&state_dir)?;
            let statement = node.attest(&std::fs::read(request)?, now_unix_ms()?)?;
            write_new(&output, &statement.to_cbor()?)?;
            println!("{}", output.display());
        }
        Command::Status { state_dir } => {
            let node = WitnessNode::load(&state_dir)?;
            println!("{}", serde_json::to_string_pretty(&node.status())?);
        }
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
