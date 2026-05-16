use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct ThreatBook {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    data: Option<Data>,
}

#[derive(Deserialize)]
struct Data {
    sub_domains: Option<SubDomains>,
}

#[derive(Deserialize)]
struct SubDomains {
    data: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for ThreatBook {
    fn name(&self) -> &'static str {
        "threatbook"
    }
    fn is_default(&self) -> bool {
        false
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

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return empty_stream(),
        };

        let url = format!(
            "https://api.threatbook.cn/v3/domain/sub_domains?apikey={key}&resource={domain}"
        );

        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &[])
            .await
        {
            Ok(r) => r,
            Err(_) => return empty_stream(),
        };
        if !resp.status().is_success() {
            return empty_stream();
        }

        let text = match resp.text().await {
            Ok(t) => t,
            Err(_) => return empty_stream(),
        };

        let mut all = Vec::new();

        if let Ok(parsed) = serde_json::from_str::<Resp>(&text) {
            if let Some(subs) = parsed
                .data
                .and_then(|d| d.sub_domains)
                .and_then(|sd| sd.data)
            {
                for s in subs {
                    let s = s.trim().to_ascii_lowercase();
                    // API may return bare prefix (e.g. "www") or full subdomain
                    let host = if extractor::is_subdomain(&s, domain) {
                        s
                    } else if !s.contains('.') {
                        format!("{s}.{domain}")
                    } else {
                        continue;
                    };
                    if extractor::is_subdomain(&host, domain) {
                        all.push(host);
                    }
                }
            }
        }

        // Fallback
        if all.is_empty() {
            all.extend(extractor::extract(&text, domain));
        }

        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
