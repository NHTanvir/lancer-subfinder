# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-subfinder` — A Rust clone of the popular `subfinder` subdomain enumeration tool, built as part of the Lancer 2026 AI-era bug-bounty toolkit. It performs passive subdomain discovery by querying dozens of third-party OSINT sources and DNS resolvers. The tool is currently in active development (scaffold stage), with the full implementation roadmap tracked in the local `plan.md`.

## Architecture

- `src/main.rs` — Binary entry point; wires CLI args into the async runtime and kicks off the engine.
- `src/lib.rs` — Library entry point; re-exports public types and modules for potential programmatic use.
- `src/cli.rs` — CLI surface built with `clap` (derive macros); defines all user-facing flags and subcommands.
- `src/engine.rs` — Core enumeration engine; orchestrates concurrent source queries, rate-limiting, and result merging.
- `src/resolve.rs` — DNS resolution layer using `hickory-resolver`; validates discovered subdomains.
- `src/extractor.rs` — Subdomain extraction logic (regex-based) applied to raw source responses.
- `src/config.rs` — Configuration loading from YAML/JSON (API keys, source toggles, resolver settings).
- `src/session.rs` — Session state and checkpoint management for resumable runs.
- `src/checkpoint.rs` — Serialisation/deserialisation of scan progress for crash recovery.
- `src/output.rs` — Output formatters (JSON, plain text, etc.) and file-writing helpers.
- `src/logging.rs` — `tracing`-based structured logging setup with `env-filter` support.
- `src/stats.rs` — Runtime statistics collection (sources hit, subdomains found, errors, timing).
- `src/ai_rank.rs` — AI-assisted result ranking/prioritisation module (Lancer-specific extension).
- `src/sources/` — One file per passive OSINT source (50+ sources: crt.sh, Shodan, VirusTotal, GitHub, etc.); all implement a common async trait from `src/sources/mod.rs`.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI is gated behind the default `gui` feature; `--no-default-features` builds a headless CLI binary.
- Library code lives in `src/lib.rs`; binary entry point in `src/main.rs`.
- Each OSINT source lives in its own file under `src/sources/` and must implement the shared source trait defined in `src/sources/mod.rs`.
- Async concurrency is managed with `tokio` (multi-thread runtime); rate-limiting uses the `governor` crate to respect per-source API limits.
- DNS resolution uses `hickory-resolver` with system-config support; do not use `std` blocking DNS calls anywhere in async paths.
- Structured logging via `tracing` macros (`trace!`, `debug!`, `info!`, `warn!`, `error!`) — never use `println!` for runtime output in library code.

## Build / test / run

```
build.bat                   # Windows → build\lancer-subfinder.exe
build-windows.bat           # Windows packaged dist → dist\lancer-subfinder-windows-x86_64\bin\lancer-subfinder.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # unit + integration tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored; if ever tracked, run `git rm --cached plan.md`.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
