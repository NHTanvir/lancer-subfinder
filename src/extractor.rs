//! Subdomain extractor — a per-apex compiled regex that pulls valid
//! `*.apex` hostnames out of raw text (cert SANs, archived URLs, etc.).

use std::sync::Arc;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;

static EXTRACTORS: Lazy<DashMap<String, Arc<Regex>>> = Lazy::new(DashMap::new);

/// Returns a (cached) regex matching any subdomain of `apex`.
pub fn for_apex(apex: &str) -> Arc<Regex> {
    let key = apex.to_ascii_lowercase();
    if let Some(r) = EXTRACTORS.get(&key) {
        return r.clone();
    }
    let escaped = regex::escape(&key);
    let pat = format!(
        r"(?i)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9_-]{{0,61}}[a-z0-9])?\.)+{escaped}\b",
        escaped = escaped
    );
    let re = Arc::new(Regex::new(&pat).expect("valid subdomain regex"));
    EXTRACTORS.insert(key, re.clone());
    re
}

/// Extract all `*.apex` hosts from a blob of text, lowercased,
/// deduped, with leading `*.` stripped.
pub fn extract(text: &str, apex: &str) -> Vec<String> {
    let re = for_apex(apex);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for m in re.find_iter(text) {
        let mut s = m.as_str().to_ascii_lowercase();
        if let Some(rest) = s.strip_prefix("*.") {
            s = rest.to_string();
        }
        if seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

/// Test a hostname against the apex.
pub fn is_subdomain(host: &str, apex: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let a = apex.trim().trim_end_matches('.').to_ascii_lowercase();
    h == a || h.ends_with(&format!(".{a}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_from_url() {
        let text = "https://api.foo.com/path  staging.foo.com bar baz.foo.com.evil.com";
        let mut got = extract(text, "foo.com");
        got.sort();
        assert!(got.contains(&"api.foo.com".to_string()));
        assert!(got.contains(&"staging.foo.com".to_string()));
    }

    #[test]
    fn strips_wildcard() {
        let text = "*.dev.foo.com";
        let got = extract(text, "foo.com");
        assert_eq!(got, vec!["dev.foo.com"]);
    }
}
