//! GitHub code search. Multi-token round-robin; follows Link: rel="next".

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use regex::Regex;
use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct GitHub {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    items: Option<Vec<Item>>,
}
#[derive(Deserialize)]
struct Item {
    html_url: Option<String>,
    text_matches: Option<Vec<Match>>,
}
#[derive(Deserialize)]
struct Match {
    fragment: Option<String>,
}

#[async_trait::async_trait]
impl Source for GitHub {
    fn name(&self) -> &'static str {
        "github"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Required
    }
    fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        if self.keys.is_empty() {
            return super::empty_stream();
        }

        let mut out = Vec::new();
        let mut url = format!(
            "https://api.github.com/search/code?per_page=100&q={domain}&sort=created&order=asc"
        );
        for _ in 0..5 {
            let key = match super::next_key(&self.keys, &self.rr) {
                Some(k) => k,
                None => break,
            };
            let headers = vec![
                ("Authorization", format!("Bearer {key}")),
                ("Accept", "application/vnd.github.text-match+json".into()),
            ];
            let resp = match session
                .req(self.name(), reqwest::Method::GET, &url, None, &headers)
                .await
            {
                Ok(r) => r,
                Err(_) => break,
            };
            if !resp.status().is_success() {
                break;
            }
            let next = parse_link_next(resp.headers().get("link"));
            let body: Resp = match resp.json().await {
                Ok(v) => v,
                Err(_) => break,
            };
            for it in body.items.unwrap_or_default() {
                if let Some(u) = it.html_url {
                    out.extend(extractor::extract(&u, domain));
                }
                for m in it.text_matches.unwrap_or_default() {
                    if let Some(f) = m.fragment {
                        out.extend(extractor::extract(&f, domain));
                    }
                }
            }
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}

fn parse_link_next(h: Option<&reqwest::header::HeaderValue>) -> Option<String> {
    let v = h?.to_str().ok()?;
    static LINK_RE: once_cell::sync::Lazy<Regex> = once_cell::sync::Lazy::new(|| {
        Regex::new(r#"<([^>]+)>;\s*rel="next""#).unwrap()
    });
    LINK_RE.captures(v).map(|c| c[1].to_string())
}
