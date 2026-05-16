//! Clap-derive CLI. Mirrors the original subfinder option groups.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgAction, Parser};

use crate::config::{ProviderConfig, RuntimeConfig};
use crate::engine::Engine;
use crate::output::{OutputFormat, OutputWriter};
use crate::sources::registry::Registry;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lancer-subfinder",
    version,
    about = "Passive subdomain enumeration across 30+ sources (Rust clone of subfinder)",
    long_about = None,
)]
pub struct Cli {
    // ---------------- INPUT ----------------
    /// Target apex domains (comma separated)
    #[arg(short = 'd', long = "domain", value_delimiter = ',', help_heading = "Input")]
    pub domains: Vec<String>,

    /// File of newline-separated domains
    #[arg(short = 'D', long = "dL", help_heading = "Input")]
    pub domain_list: Option<PathBuf>,

    // ---------------- SOURCE ----------------
    /// Comma-separated source whitelist
    #[arg(short = 's', long = "sources", value_delimiter = ',', help_heading = "Source")]
    pub sources: Vec<String>,

    /// Comma-separated source exclude list
    #[arg(long = "exclude-sources", visible_alias = "es", value_delimiter = ',', help_heading = "Source")]
    pub exclude_sources: Vec<String>,

    /// Use all registered sources (incl. non-default)
    #[arg(long = "all", help_heading = "Source")]
    pub all: bool,

    /// Only sources that support recursive enumeration
    #[arg(long = "recursive", help_heading = "Source")]
    pub recursive: bool,

    /// List registered sources and exit
    #[arg(long = "ls", help_heading = "Source")]
    pub list_sources: bool,

    // ---------------- FILTER ----------------
    /// Match-include regex(es), comma separated
    #[arg(short = 'm', long = "match", value_delimiter = ',', help_heading = "Filter")]
    pub match_regex: Vec<String>,

    /// File of match-include regexes (one per line)
    #[arg(long = "mf", help_heading = "Filter")]
    pub match_file: Option<PathBuf>,

    /// Match-exclude regex(es), comma separated
    #[arg(short = 'f', long = "filter", value_delimiter = ',', help_heading = "Filter")]
    pub filter_regex: Vec<String>,

    /// File of match-exclude regexes
    #[arg(long = "ff", help_heading = "Filter")]
    pub filter_file: Option<PathBuf>,

    /// Drop hostnames that look like raw IPs
    #[arg(long = "exclude-ip", visible_alias = "ei", help_heading = "Filter")]
    pub exclude_ips: bool,

    // ---------------- RATE-LIMIT ----------------
    /// Global HTTP req/sec across all sources
    #[arg(long = "rate-limit", visible_alias = "rl", help_heading = "Rate-limit")]
    pub rate_limit: Option<u32>,

    /// Per-source overrides, e.g. `github=30/m,virustotal=4/m`
    #[arg(long = "rate-limits", visible_alias = "rls", value_delimiter = ',', help_heading = "Rate-limit")]
    pub rate_limits: Vec<String>,

    /// Resolver / network worker concurrency
    #[arg(short = 't', long = "threads", default_value_t = 10, help_heading = "Rate-limit")]
    pub threads: usize,

    // ---------------- OUTPUT ----------------
    /// Output file
    #[arg(short = 'o', long = "output", help_heading = "Output")]
    pub output: Option<PathBuf>,

    /// Write JSON-lines instead of plain text
    #[arg(short = 'j', long = "json", visible_alias = "oJ", help_heading = "Output")]
    pub json: bool,

    /// Write CSV (host,sources)
    #[arg(long = "csv", help_heading = "Output")]
    pub csv: bool,

    /// One output file per domain in DIR
    #[arg(long = "output-dir", visible_alias = "oD", help_heading = "Output")]
    pub output_dir: Option<PathBuf>,

    /// Collect source names per host (used with -j/--csv)
    #[arg(long = "collect-sources", visible_alias = "cs", help_heading = "Output")]
    pub collect_sources: bool,

    /// Append resolved IP after host (active mode only)
    #[arg(long = "include-ip", visible_alias = "oI", help_heading = "Output")]
    pub include_ip: bool,

    // ---------------- CONFIGURATION ----------------
    /// Main config (CLI defaults), YAML
    #[arg(long = "config", help_heading = "Configuration")]
    pub config: Option<PathBuf>,

    /// Provider/API key config, YAML
    #[arg(long = "provider-config", visible_alias = "pc", help_heading = "Configuration")]
    pub provider_config: Option<PathBuf>,

    /// HTTP/HTTPS/SOCKS proxy URL
    #[arg(long = "proxy", help_heading = "Configuration")]
    pub proxy: Option<String>,

    /// DNS resolvers (comma separated)
    #[arg(short = 'r', long = "resolvers", value_delimiter = ',', help_heading = "Configuration")]
    pub resolvers: Vec<String>,

    /// File of resolvers (one per line)
    #[arg(long = "rL", help_heading = "Configuration")]
    pub resolver_list: Option<PathBuf>,

    // ---------------- OPTIMIZATION ----------------
    /// Resolve every candidate; drop NXDOMAIN/wildcards
    #[arg(long = "active", help_heading = "Optimization")]
    pub active: bool,

    /// Same as --active but explicit wildcard removal
    #[arg(long = "no-wildcard", visible_alias = "nW", help_heading = "Optimization")]
    pub no_wildcard: bool,

    /// Per-request HTTP timeout (seconds)
    #[arg(long = "timeout", default_value_t = 30, help_heading = "Optimization")]
    pub timeout_secs: u64,

    /// Overall enumeration wall-clock (minutes)
    #[arg(long = "max-time", default_value_t = 10, help_heading = "Optimization")]
    pub max_time_mins: u64,

    // ---------------- DEBUG ----------------
    /// Suppress banner / progress (subdomains only on stdout)
    #[arg(long = "silent", action = ArgAction::SetTrue, help_heading = "Debug")]
    pub silent: bool,

    /// Verbose logs
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue, help_heading = "Debug")]
    pub verbose: bool,

    /// Print per-source stats at end
    #[arg(long = "stats", help_heading = "Debug")]
    pub stats: bool,

    // ---------------- AI ----------------
    /// Rank results via Claude (lancer-ai), if available
    #[arg(long = "ai-rank", help_heading = "AI")]
    pub ai_rank: bool,

    // ---------------- RESUME ----------------
    /// Resume a previous run: merge results with saved checkpoint for each domain
    #[arg(long = "resume", help_heading = "Optimization")]
    pub resume: bool,
}

pub async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    if !cli.silent {
        banner();
    }

    let provider = ProviderConfig::load(cli.provider_config.as_deref())?;
    let registry = Registry::with_keys(&provider);

    if cli.list_sources {
        registry.print_list();
        return Ok(ExitCode::SUCCESS);
    }

    let runtime = RuntimeConfig::from_cli(&cli)?;
    let domains = gather_domains(&cli)?;
    if domains.is_empty() {
        anyhow::bail!("no targets given. supply -d <domain> or -dL <file>");
    }

    let engine = Engine::new(runtime, registry).await?;
    let mut writer = OutputWriter::new(
        &cli.output,
        cli.output_dir.as_deref(),
        OutputFormat::from_flags(cli.json, cli.csv),
        cli.collect_sources,
    )?;

    let mut total = 0usize;
    let mut all_stats = crate::stats::Stats::default();
    for domain in &domains {
        let mut res = engine.enumerate(domain).await?;

        // Phase 8: merge checkpoint if --resume
        if cli.resume {
            let previous = crate::checkpoint::load(domain);
            if !previous.is_empty() {
                let existing: std::collections::HashSet<String> =
                    res.subdomains.iter().map(|h| h.host.clone()).collect();
                for host in previous {
                    if !existing.contains(&host) {
                        res.subdomains.push(crate::engine::SubdomainHit {
                            host,
                            sources: vec!["checkpoint".into()],
                            ip: None,
                        });
                    }
                }
                res.subdomains.sort_by(|a, b| a.host.cmp(&b.host));
            }
        }

        // Phase 9: AI ranking if --ai-rank
        if cli.ai_rank {
            let hosts: Vec<String> = res.subdomains.iter().map(|h| h.host.clone()).collect();
            let ranked = crate::ai_rank::rank(hosts).await;
            let by_host: std::collections::HashMap<String, crate::engine::SubdomainHit> = res
                .subdomains
                .into_iter()
                .map(|h| (h.host.clone(), h))
                .collect();
            res.subdomains = ranked
                .into_iter()
                .filter_map(|h| by_host.get(&h).cloned())
                .collect();
        }

        total += res.subdomains.len();
        writer.write_result(domain, &res, cli.include_ip)?;
        all_stats.merge(&res.stats);

        // Phase 8: persist checkpoint after each domain
        let all_hosts: Vec<String> = res.subdomains.iter().map(|h| h.host.clone()).collect();
        if let Err(e) = crate::checkpoint::save(domain, &all_hosts) {
            tracing::warn!("checkpoint save failed for {domain}: {e:#}");
        }
    }
    writer.finalize()?;

    if cli.stats {
        all_stats.print();
    }

    if !cli.silent {
        tracing::info!("done: {total} subdomains across {} domain(s)", domains.len());
    }
    Ok(ExitCode::SUCCESS)
}

fn banner() {
    eprintln!();
    eprintln!("    __                                ____         __");
    eprintln!("   / /___ _____  ________  _____   / __/_  ______/ /");
    eprintln!("  / / __ `/ __ \\/ ___/ _ \\/ ___/  / /_/ / / / __  / ");
    eprintln!(" / / /_/ / / / / /__/  __/ /     / __/ /_/ / /_/ /  ");
    eprintln!("/_/\\__,_/_/ /_/\\___/\\___/_/     /_/  \\__,_/\\__,_/   ");
    eprintln!("                lancer-subfinder v{}", env!("CARGO_PKG_VERSION"));
    eprintln!();
}

fn gather_domains(cli: &Cli) -> anyhow::Result<Vec<String>> {
    use std::io::{BufRead, BufReader};

    let mut out: Vec<String> = cli
        .domains
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    if let Some(path) = &cli.domain_list {
        let f = std::fs::File::open(path)
            .map_err(|e| anyhow::anyhow!("open {}: {}", path.display(), e))?;
        let mut reader = BufReader::with_capacity(1 << 20, f); // big buffer (issue #9 in plan)
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            let trimmed = line.trim().to_ascii_lowercase();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
        }
    }

    if cli.domains.is_empty() && cli.domain_list.is_none() {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                let trimmed = line.trim().to_ascii_lowercase();
                if !trimmed.is_empty() {
                    out.push(trimmed);
                }
            }
        }
    }

    out.sort();
    out.dedup();
    Ok(out)
}
