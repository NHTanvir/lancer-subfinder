//! lancer-subfinder library API.
//!
//! Used by the `lancer-subfinder` binary and by Lancer's main toolkit
//! (§37 "Bulk Probe") to enumerate subdomains programmatically.
//!
//! # Quick start
//!
//! ```no_run
//! use lancer_subfinder::{Engine, EnumerationResult, ProviderConfig, Registry, RuntimeConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let provider = ProviderConfig::default();
//!     let registry = Registry::with_keys(&provider);
//!     let cfg = RuntimeConfig::default_for_domain();
//!     let engine = Engine::new(cfg, registry).await?;
//!     let result = engine.enumerate("example.com").await?;
//!     for sub in &result.subdomains {
//!         println!("{}", sub.host);
//!     }
//!     Ok(())
//! }
//! ```

pub mod ai_rank;
pub mod checkpoint;
pub mod cli;
pub mod config;
pub mod engine;
pub mod extractor;
pub mod logging;
pub mod output;
pub mod resolve;
pub mod session;
pub mod sources;
pub mod stats;

use std::process::ExitCode;

pub use cli::Cli;
pub use config::{ProviderConfig, RuntimeConfig};
pub use engine::{EnumerationResult, Engine, SubdomainHit};
pub use sources::registry::Registry;

/// Canonical subdomain type alias used by Lancer §37 "Bulk Probe".
pub type Subdomain = SubdomainHit;

/// Run the CLI end-to-end. Returns the process exit code.
pub async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    cli::run(cli).await
}
