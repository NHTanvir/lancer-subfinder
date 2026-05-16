//! lancer-subfinder
//! Rust clone of subfinder. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-subfinder", version, about = "Rust clone of subfinder")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-subfinder - scaffold ready. Implement per plan.md.");
    Ok(())
}
