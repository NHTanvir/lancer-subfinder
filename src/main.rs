//! lancer-subfinder — Rust clone of ProjectDiscovery subfinder.
//! Passive subdomain enumeration across 30+ sources.

use std::process::ExitCode;

use clap::Parser;
use lancer_subfinder::cli::Cli;
use lancer_subfinder::run;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    lancer_subfinder::logging::init(cli.silent, cli.verbose);
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("fatal: {:#}", e);
            ExitCode::from(1)
        }
    }
}
