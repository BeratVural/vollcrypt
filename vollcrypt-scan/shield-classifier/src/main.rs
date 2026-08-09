use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use vollcrypt_scan_core::{ScanEngine, ScanLimits, ScanOptions};
use vollcrypt_shield_classifier::ShieldClassifier;

#[derive(Debug, Parser)]
#[command(name = "vollcrypt-shield-classify", version)]
struct Arguments {
    #[arg(long)]
    root: PathBuf,
    #[arg(long, default_value_t = 100_000)]
    max_files: usize,
    #[arg(long, default_value_t = 1_048_576)]
    max_file_bytes: u64,
    #[arg(long, default_value_t = 268_435_456)]
    max_total_bytes: u64,
    #[arg(long)]
    output: Option<PathBuf>,
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
    let classifier = ShieldClassifier::new()?;
    let engine = ScanEngine::new(
        &arguments.root,
        ScanOptions {
            limits: ScanLimits {
                max_files: arguments.max_files,
                max_file_bytes: arguments.max_file_bytes,
                max_total_bytes: arguments.max_total_bytes,
            },
            ..ScanOptions::default()
        },
    )?;
    let report = classifier.output(engine.scan(&classifier)?);
    let json = serde_json::to_vec_pretty(&report)?;
    if let Some(output) = arguments.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&output)?;
        use std::io::Write;
        file.write_all(&json)?;
        file.sync_all()?;
        println!("{}", output.display());
    } else {
        println!("{}", String::from_utf8(json)?);
    }
    Ok(())
}
