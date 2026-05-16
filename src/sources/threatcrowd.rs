use std::sync::Arc;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct ThreatCrowd;

#[derive(Deserialize)]
struct Resp {
    subdomains: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for ThreatCrowd {
    fn name(&self) -> &'static str {
        "threatcrowd"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!(
            "https://threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        );
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(_) => return super::empty_stream(),
        };
        let parsed: Resp = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let out: Vec<String> = parsed
            .subdomains
            .unwrap_or_default()
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty() && crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
