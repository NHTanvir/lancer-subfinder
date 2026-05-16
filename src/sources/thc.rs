use std::sync::Arc;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Thc;

#[derive(Deserialize)]
struct Resp {
    subdomains: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for Thc {
    fn name(&self) -> &'static str {
        "thc"
    }
    fn is_default(&self) -> bool {
        false
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!(
            "https://threatcrowd.io/searchApi/v2/domain/report/?domain={domain}"
        );
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        if !resp.status().is_success() {
            return super::empty_stream();
        }
        let text = resp.text().await.unwrap_or_default();
        let mut out: Vec<String> = Vec::new();

        if let Ok(parsed) = serde_json::from_str::<Resp>(&text) {
            if let Some(subs) = parsed.subdomains {
                for s in subs {
                    let s = s.trim().to_ascii_lowercase();
                    if s.is_empty() {
                        continue;
                    }
                    let host = if crate::extractor::is_subdomain(&s, domain) {
                        s
                    } else {
                        format!("{s}.{domain}")
                    };
                    if crate::extractor::is_subdomain(&host, domain) {
                        out.push(host);
                    }
                }
                out.sort();
                out.dedup();
            }
        }

        // Fallback to regex extractor if JSON parse yielded nothing
        if out.is_empty() {
            out = crate::extractor::extract(&text, domain);
        }

        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
