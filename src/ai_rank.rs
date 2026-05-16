//! AI-powered subdomain ranking via the Anthropic Claude API.
//!
//! Pass the full discovered subdomain list; receive them back sorted by
//! estimated exploit-likelihood (high → low). Reads ANTHROPIC_API_KEY from env.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const MODEL: &str = "claude-opus-4-7";
const API_URL: &str = "https://api.anthropic.com/v1/messages";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_TOKENS: u32 = 8192;

const SYSTEM_PROMPT: &str = "\
You are an expert bug-bounty security researcher specialising in subdomain \
attack surface analysis. Given a list of subdomains, rank them from highest \
to lowest likelihood of containing a high-severity vulnerability. \
\n\nConsider these signals (in order of weight):\
\n1. Admin/management/CI keywords (admin, jenkins, argo, kibana, grafana, \
jira, confluence, gitlab, sonar, nexus, vault, consul, internal, mgmt)\
\n2. Dev/staging/test environments (dev, staging, stg, uat, test, sandbox, \
preprod, qa, old, legacy, demo, beta)\
\n3. Technology hints suggesting known CVEs (wp-, wordpress, drupal, moodle, \
magento, exchange, owa, vpn, pulse, f5, citrix)\
\n4. High Shannon entropy in the subdomain label (randomly-generated = likely \
ephemeral/forgotten asset)\
\n5. Unusual third-level depth (many labels = specific service = specific CVE \
surface)\
\n\nOutput ONLY the ranked subdomain list, one per line, no numbering, no \
explanation, no extra text. Preserve exact case from input.";

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct Response {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    text: Option<String>,
}

/// Rank `subdomains` by exploit likelihood using Claude.
///
/// Returns a re-ordered vec (highest priority first). Falls back to the
/// original order on any API error so the caller always gets a usable list.
pub async fn rank(subdomains: Vec<String>) -> Vec<String> {
    match rank_inner(&subdomains).await {
        Ok(ranked) => ranked,
        Err(e) => {
            tracing::warn!("ai-rank failed, returning unranked: {e:#}");
            subdomains
        }
    }
}

async fn rank_inner(subdomains: &[String]) -> Result<Vec<String>> {
    let api_key = std::env::var("ANTHROPIC_API_KEY")
        .context("ANTHROPIC_API_KEY not set — cannot use --ai-rank")?;

    if subdomains.is_empty() {
        return Ok(Vec::new());
    }

    let list = subdomains.join("\n");
    let user_content = format!(
        "Rank these {} subdomains by exploit likelihood (highest first):\n\n{list}",
        subdomains.len()
    );

    let body = Request {
        model: MODEL,
        max_tokens: MAX_TOKENS,
        system: SYSTEM_PROMPT,
        messages: vec![Message {
            role: "user",
            content: &user_content,
        }],
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(API_URL)
        .header("x-api-key", &api_key)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .context("Claude API request failed")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("Claude API returned {status}: {body}");
    }

    let parsed: Response = resp.json().await.context("parsing Claude response")?;

    let text = parsed
        .content
        .into_iter()
        .filter(|b| b.kind == "text")
        .filter_map(|b| b.text)
        .collect::<Vec<_>>()
        .join("\n");

    // Parse the output: one subdomain per line, preserving order.
    // Filter to only lines that actually appear in the original set.
    let original: std::collections::HashSet<&str> =
        subdomains.iter().map(|s| s.as_str()).collect();

    let mut ranked: Vec<String> = text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && original.contains(l.as_str()))
        .collect();

    // Append any originals that Claude dropped (shouldn't happen but be safe)
    let seen: std::collections::HashSet<&str> = ranked.iter().map(|s| s.as_str()).collect();
    for s in subdomains {
        if !seen.contains(s.as_str()) {
            ranked.push(s.clone());
        }
    }

    Ok(ranked)
}
