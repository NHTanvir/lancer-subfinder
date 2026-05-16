use std::sync::Arc;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct AlienVault;

#[derive(Deserialize)]
struct Resp {
    passive_dns: Option<Vec<Entry>>,
}
#[derive(Deserialize)]
struct Entry {
    hostname: Option<String>,
}

#[async_trait::async_trait]
impl Source for AlienVault {
    fn name(&self) -> &'static str {
        "alienvault"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }
    fn has_recursive_support(&self) -> bool {
        true
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!(
            "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        );
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let mut out = Vec::new();
        if let Some(entries) = parsed.passive_dns {
            for e in entries {
                if let Some(h) = e.hostname {
                    let h = h.trim().to_ascii_lowercase();
                    if !h.is_empty() && crate::extractor::is_subdomain(&h, domain) {
                        out.push(h);
                    }
                }
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
