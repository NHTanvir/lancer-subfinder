# RESEARCH DOSSIER: subfinder

> Part of the Lancer ecosystem. A Rust clone of ProjectDiscovery's subfinder, the de-facto passive subdomain enumeration tool. Build with Claude Code.
> Upstream: github.com/projectdiscovery/subfinder (Go, v2.14.0 April 2026, 13.7k stars, ~50+ sources)

## Feature Parity Mandate

**`lancer-subfinder` MUST ship with 100% feature parity to the upstream `subfinder` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `subfinder --help` (and the long-form man page / docs) must work in `lancer-subfinder --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-subfinder` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-subfinder --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does (1-paragraph)
subfinder fans out a target apex domain to 50+ external passive data sources (cert transparency logs, threat-intel feeds, search-engine indexes, DNS aggregators, code search) in parallel, deduplicates the streamed subdomain results into a single set, optionally resolves them through a DNS resolver pool (`-active`/`-nW` modes) and optionally filters wildcard noise. The output is one subdomain per line on stdout (or jsonl/file), designed to be the head of a recon pipe — `subfinder -d acme.com | dnsx | httpx | nuclei`. It is **purely passive** — it never sends a packet to the target — which is the key property hunters rely on for stealth and scope-safety.

## Internal architecture (file-level, dev branch as of May 2026)

- **`cmd/subfinder/main.go`** — thin entry: parses options, calls `runner.NewRunner`, calls `RunEnumeration`.
- **`pkg/runner/`** — orchestration layer.
  - `options.go` (~400 LOC) — `goflags`-based CLI parser with grouped flags (input/source/filter/rate-limit/output/configuration/optimization/debug/update). Owns the `Options` struct and the `defaultRateLimits` table (`github=83/m`, `hackertarget=2/s`, `securitytrails=2/s`, `virustotal=4/m`, `whoisxmlapi=50/s`, `urlscan=1/s`, etc.).
  - `runner.go` — `Runner` holds `*passive.Agent`, `*resolve.Resolver`, `*subscraping.CustomRateLimit`. `EnumerateMultipleDomainsWithCtx` reads domains from stdin/file, regex-skips IPs, opens a per-domain output file when `-oD` is set, and calls `EnumerateSingleDomainWithCtx`.
  - `enumerate.go` — single-domain pipeline: calls `passive.Agent.EnumerateSubdomains*`, range-iterates the result chan, applies match/filter regex, optional wildcard removal via `resolve.Resolver`, writes via `OutputWriter`.
  - `initialize.go`, `outputter.go`, `stats.go`, `util.go`, `validate.go`, `banners.go`, `config.go`.
- **`pkg/passive/`** — the source registry.
  - `sources.go` — `var AllSources = [...]subscraping.Source{...}` holds 50 source instances (see Data Sources table). Three sources are *commented out* (`reconcloud` — Cloudflare bot protection, `riddler` — Cloudfront, `threatminer` — broken API). `init()` populates `NameSourceMap`. `New(...)` returns an `*Agent` filtered by `-s`/`-es`/`-all`/`-recursive`; pulls API keys from env (`<SOURCE>_API_KEY`).
  - `passive.go` — `EnumerateSubdomainsWithCtx` fans out: builds a `ratelimit.MultiLimiter`, spawns one goroutine per source via `sync.WaitGroup`, each source streams into a shared `chan subscraping.Result`. Respects per-source rate-limits from `defaultRateLimits` overlaid with user `-rls` overrides. Context timeout is `maxEnumTime` (default 10 min).
- **`pkg/subscraping/`** — source SDK.
  - `agent.go` — `Session` wraps an `*http.Client` with `MaxIdleConns: 100`, random user-agent (`uarand`), and a shared `MultiLimiter`. Methods: `Get/SimpleGet/Post/SimplePost/HTTPRequest`. Every request enforces the rate limit via `MultiRateLimiter.Take(sourceName)`. Non-200 responses dump the body at debug level.
  - `extractor.go` — `NewSubdomainExtractor(domain)` returns a regex extractor each source pipes its raw string output through. This is what makes the `crt.sh` / `wayback` / `hackertarget` raw-text scraping work uniformly.
  - `sources/<name>/<name>.go` — 50 source modules; each implements `Source` interface: `Run(ctx, domain, session) <-chan Result`, `Name()`, `IsDefault()`, `HasRecursiveSupport()`, `KeyRequirement()`, `AddApiKeys([]string)`, `Statistics()`.
- **`pkg/resolve/`** — `Resolver` for `-active`/`-nW`: bulk A-record resolution via `retryabledns` with the default resolver list (Cloudflare/Google/Quad9/OpenDNS), wildcard detection by querying `<sha1>.<target>` and comparing IP sets.
- **Concurrency model.** Single tokio-equivalent: one goroutine per source per domain, all writing to one result channel. No worker pool — each source manages its own internal paging and gets a single goroutine. Backpressure is provided by the consumer (the runner loop reading from the chan) and the per-source rate limiter.
- **Total LOC.** ~7-8k Go LOC (excluding tests), of which roughly 60% is the source modules. Each source averages 80-180 LOC.
- **2024-2026 trends in commits.**
  - **Mar-Apr 2026 (v2.14.0):** mass refactor of source error handling by `x-stp` — `fix(c99/shodan/submd/...): surface transport errors to results channel`, `fix(netlas): cap dl size to Community limits`, `fix(chinaz): accept empty arrays`. Pattern: replace silent error swallowing with channel sends so the stats subsystem sees them.
  - **2025-2026:** added `submd`, `merklemap`, `digitalyama`, `driftnet`, `pugrecon`, `rsecloud`, `reconeer`, `hudsonrock`, `windvane`, `profundis` — net new sources every quarter.
  - Censys migrated to **Platform API v3** (`api.platform.censys.io/v3/global/search/query`) with cursor pagination — older subfinder forks still use v2 and silently fail.

## Granular feature list (the user-visible surface)

1. `-d acme.com,foo.com` — comma-separated apex targets, `goflags.NormalizedStringSliceOptions` lowercases & dedupes.
2. `-dL list.txt` — newline-separated targets; one output file per target when combined with `-oD`.
3. `-s crtsh,github` — explicit source whitelist (case-insensitive).
4. `-es alienvault,zoomeyeapi` — exclude list (applied after include/default).
5. `-all` — use every registered source even ones marked non-default (~2x slower, but +30% subdomains in practice).
6. `-recursive` — only use sources whose `HasRecursiveSupport()` returns true (currently `alienvault`, `censys`, `digitorus`, `dnsdumpster`, etc.) — meaning sources that accept `*.sub.acme.com` and return deeper subdomains.
7. `-m foo,bar` / `-mf file` — regex match filter (post-aggregation).
8. `-f baz,quux` / `-ff file` — regex exclude filter.
9. `-rl 100` — global HTTP rate limit (req/sec, all sources combined).
10. `-rls hackertarget=10/m,virustotal=4/m` — per-source rate-limit map with duration suffixes (`/s`, `/m`, `/ms`, `/h`).
11. `-t 10` — concurrent goroutines for **resolver** workers (only matters with `-active`).
12. `-o out.txt` / `-oJ` / `-oD dir/` / `-cs` — file, JSON-lines, per-domain dir, "collect-sources" (in JSON output, list which sources hit each subdomain).
13. `-config ~/.config/subfinder/config.yaml` — main config (CLI defaults).
14. `-pc ~/.config/subfinder/provider-config.yaml` — API key map: `securitytrails: [key1, key2]`, `censys: [pat:org_id]`, `github: [tok1, tok2]`.
15. `-r 8.8.8.8,1.1.1.1` / `-rL resolvers.txt` — resolver list for `-active`.
16. `-active` / `-nW` — DNS-resolve every candidate, drop ones that don't resolve, drop wildcard matches.
17. `-proxy http://127.0.0.1:8080` — HTTP/HTTPS proxy applied to all source sessions (useful for Burp inspection of source traffic).
18. `-ei` — exclude entries that look like raw IPs from final output.
19. `-oI` — append resolved IP in output (`sub.foo.com:1.2.3.4`).
20. `-timeout 30` — per-request HTTP timeout (sec).
21. `-max-time 10` — overall enumeration wall-clock (min). Cancels in-flight sources via ctx.
22. `-silent` — only subdomains on stdout (no banner/info).
23. `-ls` — list every registered source, mark `*` for required-key, `~` for optional-key.
24. `-stats` — print per-source `requests/errors/results/time` table at end.
25. **Hidden: env-var API keys.** `<SOURCEUPPER>_API_KEY=...` overrides provider-config.yaml. Example: `SECURITYTRAILS_API_KEY=xxx CENSYS_API_KEY=pat:org subfinder -d acme.com -all`. Multi-key via comma in env.
26. **Hidden: GitHub token rotation.** `pkg/subscraping/sources/github/tokenmanager.go` rotates among multiple GH tokens; if one hits 403, picks another. Multiple tokens via `github: [tok1, tok2, tok3]` in YAML.
27. **Hidden: crt.sh dual-mode.** Tries direct Postgres TCP `host=crt.sh user=guest dbname=certwatch` first (fast, can return millions of rows); falls back to `https://crt.sh/?q=%25.X&output=json` HTTP only if SQL fails. Caps at `LIMIT 10000` unless `-all` is set.
28. **Hidden: VirusTotal cursor pagination.** Uses `meta.cursor` not page numbers — older clones get only the first 40 results.
29. **Hidden: SecurityTrails scroll API.** `POST /v1/domains/list?scroll=true` returns a `scroll_id`, subsequent `GET /v1/scroll/<id>` until empty.

## Engineering hard parts (the 80/20 of getting this right)

1. **Source heterogeneity.** No two sources speak the same protocol. crt.sh is Postgres-over-TLS *and* HTTP fallback. SecurityTrails is scroll-cursor. Censys Platform is cursor-token in a POST body. VirusTotal is page-cursor in a query string. GitHub is REST search with Link-header pagination. fofa is base64-encoded query. dnsdumpster scrapes HTML+CSRF token. Each one needs bespoke pagination and bespoke error handling — there is no shortcut.
2. **Rate limits are per-source and provider-published nowhere.** subfinder's `defaultRateLimits` table is empirically derived. Hit them too hard and you get banned (e.g., `securitytrails` rate-limits aggressively at 2/s; `virustotal` free tier is 4/min, `whoisxmlapi` allows 50/s). The HTTP 429 reaction must be backoff, not retry-immediate.
3. **Wildcard DNS.** `*.herokuapp.com`, `*.github.io`, `*.cloudfront.net` resolve everything. You must probe a random `<sha1>.target.com` and capture the wildcard A-set, then drop final results whose IPs are 100% subsets. Doing this *before* writing output (vs. after) determines if your pipeline is usable.
4. **Subdomain extraction from raw text.** Sources like waybackarchive return raw URLs (`http://foo.acme.com/path?q=1`); hackertarget returns `host,ip` lines; crt.sh returns multi-line CN/SAN fields joined by `\n`. The shared `SubdomainExtractor` regex pulls valid subdomains out of all of it — but you have to handle internationalized domains, leading wildcards (`*.foo.acme.com`), and email-like prefixes.
5. **GitHub source is rate-bound per token, not per IP.** A multi-token round-robin is essential — 30 search reqs/min per token, so 3 tokens = 90/min. Misuse the same token concurrently → 403 for the whole minute.
6. **Cloudflare bot protection on free sources.** RapidDNS, ReconCloud, Riddler, Anubis, etc. periodically gate behind Cloudflare. subfinder's `corpix/uarand` random-UA helps but isn't enough; you'll sometimes need a real browser (chromedp / headless Chromium / FlareSolverr) for the toughest ones. The Go code just disables those sources when they break.
7. **crt.sh is a single point of failure.** It's the highest-yield source for most targets, runs on a single Postgres instance at Sectigo, and goes down regularly. Build a retry+fallback path *and* respect their query timeouts (`statement_timeout=<n>ms`).
8. **Output deduplication is at the *registered name* level after lowercasing + trim.** Don't dedupe on raw bytes (`Foo.Acme.Com` vs `foo.acme.com`).
9. **STDIN buffer size.** `bufio.NewScanner(reader)` defaults to 64KB — a single line of input above that is silently dropped. Set a larger buffer for very long input lines.
10. **Wildcard *threshold* matters.** dnsx's "wildcard threshold" of 5 subdomains-pointing-at-same-IP-before-suspicion is a heuristic — too low triggers false positives on small CDN deployments, too high lets junk through.

## Rust library mapping

| Original Go component | Recommended Rust crate | Version (May 2026) | Notes |
| --- | --- | --- | --- |
| `goflags` CLI | `clap` (derive) | 4.5.x | Groups via `#[command(next_help_heading="...")]`; supports YAML-config-merging via `clap-serde`. |
| `gologger` | `tracing` + `tracing-subscriber` | 0.1.x / 0.3.x | Structured + leveled; pair with `tracing-indicatif` for progress. |
| `http.Client` (`MaxIdleConns:100`) | `reqwest` | 0.12.x | `Client::builder().pool_max_idle_per_host(100).user_agent(...)` — match subfinder's pool sizing. Use rustls (`rustls-tls`) for static cross-compile. |
| `corpix/uarand` (random UA) | `fake-user-agent` or hardcoded slice | 0.1 | Trivial to inline a list of 50 strings and rand-pick. |
| `ratelimit.MultiLimiter` | `governor` + `DashMap<String, RateLimiter>` | 0.6.x | `governor::RateLimiter::keyed` is the per-source variant. |
| `sync.WaitGroup` + `chan Result` | `tokio::sync::mpsc::channel` + `JoinSet` | 1.40+ | `JoinSet::spawn` per source, drain via `while let Some` from a shared `mpsc::Sender`. |
| `database/sql` + `lib/pq` (crt.sh Postgres) | `tokio-postgres` (+ `rustls-tokio-postgres`) | 0.7.x | Async, supports parameterized queries, can set `statement_timeout` per session. |
| `jsoniter` JSON | `serde_json` (or `simd-json` for hot paths) | 1.0.x / 0.13.x | `simd-json` is 2-3x faster on large CDX/cert dumps. |
| `tomnomnom/linkheader` (GH paging) | `link-header-parser` or `hyperx::header::Link` | 0.3.x | GitHub `Link: <...>; rel="next"` parsing. |
| `gjson`-style cherry-picking | `serde_path_to_error` + `serde_json::Value` | 0.1.x / 1.0.x | Better than ad-hoc string searching for nested API responses. |
| `golang.org/x/exp/maps` | `std::collections::HashMap` + `HashSet` | — | Use `IndexSet` from `indexmap` if insertion order matters for output. |
| `regexp` subdomain extractor | `regex` (compile once via `OnceCell<Regex>`) | 1.11.x | Per-target regex — wrap in `OnceCell<HashMap<String, Regex>>` keyed on apex. |
| `fileutil.FileExists` | `tokio::fs::metadata` | 1.40+ | — |
| `goconfig` YAML provider-config | `serde_yaml` (yaml 0.9) or `serde_yml` (yaml 1.2) | 0.9 / 0.0.12 | `serde_yml` is the maintained fork; YAML 1.2 round-trips. |
| `chaos-client` SDK | call ProjectDiscovery Chaos API directly (`https://dns.projectdiscovery.io/dns/<domain>/subdomains` + bearer) | — | No need for a Go SDK port; direct REST with `reqwest`. |
| `corpix/uarand` random UA | — | — | Just embed a Vec<&str> of 50 UAs and `rand::seq::SliceRandom::choose`. |
| `subdomain.txt` brute wordlist (not present in subfinder but standard pair) | `include_bytes!("wordlists/best-dns.txt")` | — | For an optional active brute submode. |

## Data sources (the comprehensive table — 50 sources)

API rate limits & auth scheme as of May 2026. "key" column: ★ required, ◇ optional, — none.

| Source | Endpoint(s) | Auth | Rate limit | Notes |
| --- | --- | --- | --- | --- |
| **alienvault** (OTX) | `https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns` | ★ Bearer | ~ unl. | Free key; 100 records per call (no paging needed). |
| **anubis** | `https://jonlu.ca/anubis/subdomains/{d}` | — | low | Sometimes Cloudflare-gated. |
| **bevigil** | `https://osint.bevigil.com/api/{d}/subdomains/` | ★ X-Access-Token | 100/d free | Mobile-app subdomain index. |
| **bufferover** | `https://tls.bufferover.run/dns?q=.{d}` | ★ x-api-key | varies | TLS SAN dataset. |
| **builtwith** | `https://api.builtwith.com/v21/api.json?KEY=...&LOOKUP={d}` | ★ key | tier-based | Tech-stack DB; expensive. |
| **c99** | `https://api.c99.nl/subdomainfinder?key=...&domain={d}` | ★ key | 100/d | Cheap key. |
| **censys** | `POST https://api.platform.censys.io/v3/global/search/query` body `{query: "cert.names: {d}", page_size: 100, cursor: ...}` | ★ Bearer PAT (+ X-Organization-ID header) | 100 hits × 10 pages max | **Platform API v3** since 2025. Cert.names search. |
| **certspotter** | `https://api.certspotter.com/v1/issuances?domain={d}&include_subdomains=true&expand=dns_names` | ◇ Bearer | 100 reqs/h unauth, 250/h auth | CT log mirror. |
| **chaos** | `https://dns.projectdiscovery.io/dns/{d}/subdomains` (via `chaos-client` SDK) | ★ Bearer | per-tier | PD's own subdomain corpus; free tier exists. |
| **chinaz** | `https://apidata.chinaz.com/CallAPI/Alexa?key=...&domain={d}` | ★ key | per-tier | Chinese registrar-side. |
| **commoncrawl** | `http://index.commoncrawl.org/CC-MAIN-{idx}-index?url=*.{d}/*&output=json&fl=url` (latest index from `https://index.commoncrawl.org/collinfo.json`) | — | unl. | Pulls all URLs, regex-extracts subs. Slow (~250MB indexes). |
| **crtsh** | (1) Postgres `psql://guest@crt.sh/certwatch` SQL `SELECT array_to_string(NAME_VALUES,'\n') ... WHERE NAME_VALUE ILIKE '%X%' LIMIT 10000` (without `-all`); (2) HTTP fallback `https://crt.sh/?q=%25.{d}&output=json`. | — | unl. but slow | **The yield king.** Often >50% of all subs come from here. |
| **digitalyama** | `https://api.digitalyama.com/subdomain_finder?domain={d}` | ★ x-api-key | per-tier | Newer (added 2025). |
| **digitorus** | `https://certificatedetails.com/api/list/{d}` | — | low | CT/web-cert aggregator. |
| **dnsdb** | `https://api.dnsdb.info/lookup/rrset/name/*.{d}/ANY?limit=10000` | ★ X-API-Key (Farsight) | per-tier | Premium passive DNS; large. |
| **dnsdumpster** | scrapes HTML form on `https://dnsdumpster.com` with CSRF token, then POST | — | strict | Cloudflare-protected. |
| **dnsrepo** | `https://dnsrepo.noc.org/api/?apikey=&search={d}` | ◇ | unl. | Free passive DNS aggregator. |
| **domainsproject** | `https://www.domainsproject.org/lookup?d={d}` | — | unl. | Static CT-derived dataset. |
| **driftnet** | `https://api.driftnet.io/v1/scan/domains?host={d}` | ★ Bearer | per-tier | Newer. |
| **fofa** | `https://fofa.info/api/v1/search/all?email=...&key=...&qbase64=<b64('domain="{d}"')>&size=10000` | ★ email+key | per-tier | Chinese internet search. |
| **fullhunt** | `https://fullhunt.io/api/v1/domain/{d}/subdomains` | ★ X-API-KEY | 60/m free | Modern; free tier OK. |
| **github** | `https://api.github.com/search/code?per_page=100&q={d}&sort=created&order=asc` then follow `Link: rel="next"` | ★ Bearer (tok rotation) | 30/m per token | Source-code dorking; deep but rate-bound. |
| **gitlab** | `https://gitlab.com/api/v4/search?scope=blobs&search={d}` | ★ Bearer | per-tier | Less-mined than GH. |
| **hackertarget** | `https://api.hackertarget.com/hostsearch/?q={d}` (CSV `host,ip`) | ◇ | 2/sec | Always works; small yield. |
| **hudsonrock** | `https://cavalier.hudsonrock.com/api/json/v2/osint-tools/stealers-by-domain?domain={d}` | ★ key | 5/sec | Infostealer-leak DB; surfaces dev hosts. |
| **intelx** | `https://2.intelx.io/phonebook/search` body `{term:"{d}", maxresults:100000}`; `GET /phonebook/search/result?id=<id>` | ★ x-key | tier | Phonebook search. |
| **leakix** | `https://leakix.net/api/subdomains/{d}` | ◇ api-key | per-tier | Modern; free tier OK. |
| **merklemap** | `https://api.merklemap.com/v1/search?query=*.{d}` | ★ Bearer | per-tier | CT log monitor (newer). |
| **netlas** | `https://app.netlas.io/api/domains/?q=domain:*.{d}` | ★ X-API-Key | Community plan capped (fix in Apr 2026 to respect cap) | Search-engine over net data. |
| **onyphe** | `https://www.onyphe.io/api/v2/summary/domain/{d}` | ★ Bearer | per-tier | Net-recon search. |
| **profundis** | `https://api.profundis.dev/api/v1/subdomains?domain={d}` | ★ Bearer | per-tier | Newer (added 2025). |
| **pugrecon** | `https://api.pugrecon.com/api/v1/domain/{d}/subs` | ★ Bearer | 10/s | Newer (added 2025). |
| **quake** | `https://quake.360.cn/api/v3/search/quake_service` body `{query:"domain:\"{d}\""}` | ★ X-QuakeToken | per-tier | Chinese (360). |
| **rapiddns** | `https://rapiddns.io/subdomain/{d}?full=1` HTML scrape | — | Cloudflare-gated | HTML-table parse. |
| **reconcloud** | (disabled — Cloudflare bot protection) | | | Commented out in `sources.go`. |
| **reconeer** | `https://api.reconeer.com/api/subdomains?domain={d}` | ★ Bearer | per-tier | Newer. |
| **redhuntlabs** | `https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={d}&page_size=1000&page=N` | ★ Bearer | per-tier | Community endpoint. |
| **riddler** | (disabled — Cloudfront) | | | Commented out. |
| **robtex** | `https://www.robtex.com/dns-lookup/{d}` HTML scrape | — | strict | Limited per-IP. |
| **rsecloud** | `https://api.rsecloud.com/api/v1/passive-dns/{d}` | ★ Bearer | per-tier | Newer. |
| **securitytrails** | `POST https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=true` body `{query:"apex_domain='{d}'"}`; then `GET /v1/scroll/<scroll_id>` until empty | ★ APIKEY header | 2/s (paid), 50/m (free) | The other yield king. Always 200 with `scroll_id` even when more — must page until empty `records`. |
| **shodan** | `https://api.shodan.io/dns/domain/{d}?key=...` | ★ key | 1/s | Free-tier limited. |
| **sitedossier** | `http://www.sitedossier.com/parentdomain/{d}` HTML scrape | — | 8/m | Very slow but unique data. |
| **submd** | `https://api.submd.dev/api/subdomains?domain={d}` | ★ key | per-tier | Newest source (added Apr 2026). |
| **thc** | `https://threatcrowd.io/searchApi/v2/domain/report/?domain={d}` | — | unl. | (Sometimes flaky.) |
| **threatbook** | `https://api.threatbook.cn/v3/domain/sub_domains?apikey=...&resource={d}` | ★ key | per-tier | Chinese threat-intel. |
| **threatcrowd** | `https://threatcrowd.org/searchApi/v2/domain/report/?domain={d}` | — | low | Sometimes offline. |
| **threatminer** | (disabled — broken API) | | | Commented out. |
| **urlscan** | `https://urlscan.io/api/v1/search/?q=domain:{d}&size=100` then `search_after=<sort>` for next | ◇ API-Key | 1/s (anon), higher with key | Returns URLs, regex-extract subs. |
| **virustotal** | `https://www.virustotal.com/api/v3/domains/{d}/subdomains?limit=40&cursor=<c>` | ★ x-apikey | 4/min (free) | Cursor paged. |
| **waybackarchive** | `http://web.archive.org/cdx/search/cdx?url=*.{d}/*&output=txt&fl=original&collapse=urlkey` | — | 15/m | Returns URLs (TXT lines). |
| **whoisxmlapi** | `https://subdomains.whoisxmlapi.com/api/v1?apiKey=...&domainName={d}` | ★ key | 50/s | Premium. |
| **windvane** | `https://api.windvane.io/v1/subdomains?domain={d}` | ★ key | per-tier | Newer. |
| **zoomeyeapi** | `https://api.zoomeye.org/domain/search?q={d}&page=N&type=1` | ★ API-KEY | per-tier | Chinese internet search. |

## 2024-2026 state (what changed, forks, competitors)

- **subfinder is winning.** 13.7k stars, monthly releases, ~5 new sources/year. The de-facto baseline every bug bounty methodology starts with. v2.14.0 (Apr 2026) is the current stable.
- **Censys cutover.** v2.13 forced migration from Search API v2 to **Platform API v3** (`api.platform.censys.io`). Old keys broke; need Personal Access Token + Organization ID. This caught a lot of users in early 2026.
- **chaos got harder to use.** PD made `chaos-client` API key-gated for higher tiers; free tier still works but caps daily queries.
- **New sources added 2024-2026.** `submd`, `merklemap`, `digitalyama`, `pugrecon`, `rsecloud`, `reconeer`, `hudsonrock`, `windvane`, `profundis`, `driftnet`. Three were retired (riddler/threatminer/reconcloud).
- **Forks worth knowing:**
  - **Subdominator** (Revolt Securities) — Python; markets itself on "more APIs" but is ~30% slower in benchmarks. Useful as a second pass.
  - **OWASP Amass** — broader (DNS bruteforce, ASN expansion, graph DB) but slower and heavier (~10× memory). Amass passive mode pulls from 80+ sources but the union with subfinder is ~95%.
  - **Assetfinder** (tomnomnom) — old, narrow, sometimes still finds 1-2 unique hosts. Nostalgia mode.
- **Performance.** subfinder returns ~200-500 subdomains for an average domain in 30 seconds; on a typical apex like `tesla.com` with `-all` it returns thousands in 2-3 minutes (limited by SecurityTrails/VirusTotal pagination).
- **Community sentiment (r/bugbounty, r/netsec May 2026).** Universal recommendation. Common complaint: API key juggling pain and source flakiness. Common workflow: `subfinder + amass passive` for breadth, dedupe.

### Research note — 2026-05-31 (additional gaps from second-pass deep dive)

Direct walk of `github.com/projectdiscovery/subfinder/releases` v2.7.0 through v2.14.0. Items the earlier pass missed, by version:

- **v2.14.0 (27 Apr 2026).** New source: `submd` (Sub.md). **Removed**: `facebook` (Meta CT API discontinued) — the parity-tagged list must drop this. Per-source rate-limit handling now distinguishes "global" vs "per-source" — `defaultRateLimits` table grew. Control-flow fixes in `c99`, `shodan`, `submd`, `chinaz`, `intelx`, `hackertarget`. `netlas` community-tier hardcoded to 200-result download cap.
- **v2.13.0 (09 Mar 2026).** New source: `urlscan` (URLScan.io). `crtsh` got a hard timeout-resolution fix (single Postgres instance was hanging on long-running queries). `leakix` flipped from "optional API key" to "required API key" — `KeyRequirement()` returns `Required` now.
- **v2.12.0 (12 Jan 2026).** New source: `reconeer`. `hackertarget` gained optional API key support (free tier still works keyless). New `-stats` flag (live per-source request/error/results/time table — surfaces in our `Statistics()` GUI panel). **Optional-key framework** added: a source can now declare "key gives more quota" without being "key required". Three-state `KeyRequirement()` enum: `None | Optional | Required`.
- **v2.11.0 (19 Dec 2025).** New sources: `profundis`, `merklemap`, `thc`. Context cancellation now propagates cleanly through all source goroutines (no goroutine leak on `--max-time`). Censys API adaptation (early v3 endpoint).
- **v2.10.0 (19 Nov 2025).** New sources: `windvane`, `onhype`, `domainsproject`. **Removed**: `hunter` (API discontinued by vendor). Wildcard certificate detection added to JSON output schema — emit `wildcard: true` when source returns a `*.domain` cert SAN. Internal `strings.Builder` perf optimization.
- **v2.9.0 (26 Sep 2025).** New source: `driftnet`. **Environment-variable expansion in `provider-config.yaml`** — `securitytrails: [$ST_KEY]` now resolves at load time. Module restructure: moved Go module path from `v2/` subdir to repo root.
- **v2.8.0 (20 Jun 2025).** New sources: `pugrecon`, `rsecloud`. **Removed**: `binaryedge` (API discontinued). Dockerfile build correction. `hunter` and `quake` pagination fixes.
- **v2.7.0 (27 Feb 2025).** New sources: `threatcrowd` (re-added with new endpoint), `digitalyama`. **Removed**: `passivetotal` (RiskIQ acquired by Microsoft, API broke). `dnsrepo` endpoint URL changed. `anubis` non-200 responses now filtered (was producing garbage subdomains).
- **API-key framework state machine.** Three states for our `KeyRequirement` Rust enum:
  - `None` (works keyless, no quota benefit): `crtsh`, `wayback`, `commoncrawl`, `dnsrepo`, `anubis`, `hackertarget` (free tier), `submd`, `digitalyama`, `urlscan`.
  - `Optional` (key bumps quota or unlocks fields): `hackertarget` (paid), `chaos` (paid tier), `urlscan` (paid tier).
  - `Required` (no key = source skipped): `securitytrails`, `censys`, `shodan`, `virustotal`, `whoisxmlapi`, `bevigil`, `bufferover`, `c99`, `chinaz`, `dnsdb`, `fofa`, `fullhunt`, `github`, `gitlab`, `hudsonrock`, `intelx`, `leakix`, `netlas`, `passivetotal`, `quake`, `redhuntlabs`, `robtex`, `social-searcher`, `threatbook`, `zoomeye-api`, `reconeer`, `merklemap`, `thc`, `windvane`, `onhype`, `profundis`, `domainsproject`.
- **Source retirement graveyard (must not be in default registry).** `riddler`, `threatminer`, `reconcloud`, `hunter`, `binaryedge`, `passivetotal`, `facebook` — these MUST appear in our compatibility layer as "deprecated, returns empty" so existing `-s riddler` invocations don't error.
- **`-stats` output format.** Tab-separated table: `source | reqs | errs | results | time(s) | rate-limit-hit?`. We mirror in our `Statistics` JSON, plus a sortable GUI panel.
- **Optional-key behavior nuance.** When a source is `Optional` and no key is present, it must still run keyless (don't skip), but emit a warning-level message to the stats panel: "running keyless, quota limited". Our enum implementation must enforce this.

Sources: [subfinder releases](https://github.com/projectdiscovery/subfinder/releases), [subfinder v2.12.0 release notes](https://github.com/projectdiscovery/subfinder/releases/tag/v2.12.0), [v2.6.7 release](https://github.com/projectdiscovery/subfinder/releases/tag/v2.6.7).

## Real-world pipeline patterns

```bash
# Canonical recon pipe
subfinder -d acme.com -all -silent \
  | dnsx -silent -a -resp-only \
  | httpx -silent -title -tech-detect -status-code \
  | nuclei -t exposures/ -t cves/

# Multi-domain bulk
subfinder -dL roots.txt -all -oD subs/ -silent

# Live-only output
subfinder -d acme.com -all -nW -silent

# Recursive (only sources that accept *.sub.acme.com)
subfinder -d sub.acme.com -recursive -silent

# Subfinder → URLs (gau) → params (gf) → vulns
subfinder -d acme.com -silent | gau --threads 10 | gf xss | qsreplace | dalfox pipe

# Asset discovery + cdncheck filtering (skip CDN-protected hosts)
subfinder -d acme.com -all -silent | dnsx -silent -resp-only -cdn \
  | grep -v 'cdn' | naabu -p 80,443,8080,8443
```

**Failure modes in production:**

- **SecurityTrails 403** after burst → must back off 1 minute. subfinder silently drops the source until ctx-timeout.
- **GitHub 403** on a single token → with multi-token, drops to next; without, drops the source.
- **crt.sh Postgres timeout** on huge cert sets (e.g. `*.google.com`) → falls back to HTTP, which itself returns 504 → empty result. Always provide `-stats` to see who silently 0-returned.
- **Wildcard DNS targets** flood output unless `-active`/`-nW` is used: `*.appspot.com`, `*.herokuapp.com`, `*.cloudfront.net`.

## Bug bounty value + AI augmentation ideas

**Why a hunter cares in 2026.** Subdomains *are* the attack surface. Every other tool (httpx, nuclei, dirsearch, gau, dalfox) takes a subdomain list as input. Whoever has the longest *valid* subdomain list with the *most unusual* finds bugs first. Bugs uniquely surfaced by good subdomain enum: subdomain takeover (CNAME pointing at deleted SaaS), exposed staging/dev panels, forgotten admin endpoints (`old.acme.com`, `legacy.acme.com`), VPN portals (`vpn.acme.com`), CI/CD systems (`jenkins.acme.com`, `argo.acme.com`).

**AI augmentation opportunities (the Lancer differentiator):**

1. **Exploit-likelihood ranking.** Send the dedup'd subdomain list to Claude with a system prompt: "Rank these by likelihood of containing a high-severity bug. Consider: dev/staging/internal keywords, oddly-named hosts (entropy), recently-issued certs (Wayback `first_seen`), VPN/admin/jenkins/wp-admin patterns." Output top-N.
2. **Subdomain *generation*.** From discovered subs, predict missing ones via pattern induction (`v1.api.foo.com` exists → try `v2.api.foo.com`, `internal.api.foo.com`, `staging.api.foo.com`).
3. **Tech-stack inference from name.** `kibana.acme.com` → likely ELK; `jira.acme.com` → likely on-prem; `confluence.acme.com` → exploit JIRA/Confluence CVEs first.
4. **Cross-source signal fusion.** When a sub appears in cert logs but not in DNS resolution today → likely just-decommissioned. Worth probing for orphaned CNAME (takeover candidate).
5. **Smart source selection.** Given budget (req/min) and target tier (.gov vs .com), AI picks the optimal subset of sources to query — avoid wasting `whoisxmlapi` credits on dead-tier targets.
6. **Result diff over time.** Persist daily snapshots; AI generates a "what changed" diff per-target (new staging panel popped up — investigate).

## Implementation phases (10-week plan)

### Phase 0 — Skeleton & infra (Week 1)
- `cargo new lancersub`. Set up `clap` derive with the option groups (`Input`, `Source`, `Filter`, `Rate-limit`, `Output`, `Configuration`, `Debug`, `Optimization`).
- Define `pub trait Source` (async-trait): `name`, `is_default`, `has_recursive_support`, `key_requirement`, `add_api_keys`, `enumerate(ctx, domain, session) -> impl Stream<Item=Result<String>>`.
- Define `Session` wrapping `reqwest::Client` with shared `governor::RateLimiter::keyed`, random UA, optional proxy.
- Define `SubdomainExtractor` (regex `(?i)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+{apex}`).
- Deliverable: `lancersub --help` runs; `lancersub -d acme.com -ls` lists sources (none implemented yet).

### Phase 1 — 10 free, keyless sources (Week 2)
- Implement (no API key needed): `crtsh` (Postgres-first via `tokio-postgres`, HTTP fallback), `hackertarget`, `alienvault` (works keyless for some domains), `waybackarchive`, `commoncrawl`, `dnsrepo`, `threatcrowd`, `digitorus`, `anubis`, `domainsproject`.
- Wire up `tokio::sync::mpsc` orchestrator: spawn 10 tasks, drain into a `HashSet<String>`, print to stdout sorted.
- Deliverable: `lancersub -d acme.com -silent` returns hundreds of subdomains in <30 sec.

### Phase 2 — Paid/keyed sources & key management (Week 3)
- Implement: `chaos`, `securitytrails` (scroll), `virustotal` (cursor), `censys` (Platform v3 cursor with X-Organization-ID), `shodan`, `github` (Link-header + multi-token rotation), `fullhunt`, `urlscan`, `bevigil`, `c99`.
- YAML provider-config loader (`serde_yml`); env-var override (`<SOURCE>_API_KEY`); skip-if-no-key.
- Add per-source `Stats { requests, errors, results, time }` tracking surfaced via `-stats`.
- Deliverable: `lancersub -d acme.com -all -stats` produces a per-source breakdown.

### Phase 3 — Rate limiting & error surfacing (Week 4)
- `governor::Keyed` per-source token bucket. Encode `defaultRateLimits` table (see runner/options.go). Support `-rl global` and `-rls source=N/s` overlay.
- Backoff on HTTP 429 (`retry-after` honored), permanent skip on auth errors (401/403 after retry).
- Match subfinder Apr-2026 fix: every source surfaces transport errors via the result channel (not silent).
- Deliverable: `lancersub -rl 50 -rls github=30/m,virustotal=4/m -d acme.com -all` behaves correctly.

### Phase 4 — Filters, output, dedup (Week 5)
- Match/filter regex (`-m`, `-f`). Output formats: txt, JSON-lines (`{name, sources}` if `-cs`), CSV.
- `-o file`, `-oD dir` (one file per domain when `-dL`), `-oJ`.
- Exclude-IPs (`-ei`) regex skip.
- Deliverable: `lancersub -dL roots.txt -oD subs/ -oJ -cs` produces per-domain JSON-lines files with source attribution.

### Phase 5 — Active mode (DNS resolve + wildcard) (Week 6)
- `lancer-dns` shared crate (eventually exposed as LancerDNS — see dnsx clone) — built on `hickory-resolver`.
- `-nW` / `-active`: resolve every candidate; drop NXDOMAIN; detect wildcards via `<sha1>.{root}` probes (3 random probes); drop matching IPs.
- `-r resolvers.txt` resolver pool round-robin.
- `-oI` host:ip output.
- Deliverable: `lancersub -d acme.com -nW -silent` returns only resolving non-wildcard subs.

### Phase 6 — Recursive + pipelining (Week 7)
- `-recursive` filter sources by `has_recursive_support`.
- STDIN multi-domain input (line-buffered).
- `-max-time 10` ctx timeout (cancels in-flight sources cleanly).
- `-proxy` HTTPS proxy support (`reqwest::Proxy`).
- Deliverable: `cat roots.txt | lancersub -recursive -max-time 5 -silent` works.

### Phase 7 — 30+ remaining sources, source warnings & disablers (Week 8)
- Implement the remaining sources from the table (Chinese, premium, scrapers).
- HTML scrapers (rapiddns, sitedossier, robtex, dnsdumpster) via `scraper` crate (CSS selectors).
- Source-warning system: certain sources broken → emit warning, skip.
- Deliverable: source-count parity with subfinder upstream.

### Phase 8 — Statistics & resume (Week 9)
- Resume from checkpoint: persist seen-set + in-flight cursors to `~/.local/state/lancersub/<domain>.json`.
- `-stats` table printed at end.
- Update check (against `lancer` releases).
- Deliverable: kill a long enumeration with Ctrl-C, resume with `-resume`.

### Phase 9 — AI ranking + library API (Week 10)
- `--ai-rank` flag: pipe full sub list to Claude via shared `lancer-ai` crate, get ranked output back. Prompt-engineer for: admin/dev/staging keywords, entropy, technology hints, fresh-cert hints.
- Expose `lib.rs` library API: `Engine::new(opts).enumerate(domain).await -> impl Stream<Item=Subdomain>` — Lancer's main Burp clone calls this for §37 "Bulk Probe".
- Cross-platform binary release (musl, glibc, macos-arm, macos-x86, windows).
- Deliverable: `lancer-bulk-probe acme.com` (Lancer's surface map) calls into LancerSub via library, returns ranked subs.

## CLAUDE.md to seed in the clone repo
```
This project = a subfinder clone in Rust ("lancersub").
- Async via tokio; one task per source per target.
- Sources live under src/sources/<name>/, all implement async-trait Source.
- All HTTP via a single Session (reqwest with pool_max_idle_per_host=100, random UA, optional SOCKS5/HTTP proxy).
- Rate-limit via governor::keyed; defaults match the table in runner/options.go upstream.
- crt.sh is dual-mode: try Postgres (tokio-postgres) first, fall back to HTTP. SET statement_timeout=<n>ms per session.
- Wildcard detection: probe <sha1>.<target> three times, drop final results whose IPs are a subset.
- API keys via env (<SOURCE>_API_KEY) first, then YAML provider-config.
- Output is a HashSet<String> lowercased+trimmed; preserve insertion order with IndexSet if requested.
- Always surface transport errors via the result channel (do not swallow); --stats prints per-source request/error/result/time.
- NEVER block on a single slow source — per-request timeout (default 30s) + overall max-time (default 10min) + ctx cancellation.
- The library crate (lib.rs) is what Lancer §37 imports.
```

---

## GUI (Lancer-standard pattern)

`lancer-subfinder` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-subfinder-cli` companion binary), but the **plain `lancer-subfinder` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-subfinder/`, `%APPDATA%\lancer-subfinder\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-subfinder-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-subfinder.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-subfinder.exe` (double-click opens the GUI window).
- Linux: `build/lancer-subfinder` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-subfinder` (bundled into `lancer-subfinder.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-subfinder/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-subfinder.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-subfinder-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-subfinder
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-subfinder.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-subfinder-windows-x86_64\bin\lancer-subfinder.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-subfinder`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
