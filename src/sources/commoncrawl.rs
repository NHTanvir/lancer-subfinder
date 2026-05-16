use std::sync::Arc;

use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct CommonCrawl;

#[derive(Deserialize)]
struct IndexInfo {
    id: String,
    #[serde(rename = "cdx-api")]
    cdx_api: String,
}

#[async_trait::async_trait]
impl Source for CommonCrawl {
    fn name(&self) -> &'static str {
        "commoncrawl"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false // slow & heavy — only with -all
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let info = match session
            .get(self.name(), "https://index.commoncrawl.org/collinfo.json")
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let indexes: Vec<IndexInfo> = match info.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        // Use the 3 newest indexes.
        let mut all = Vec::new();
        for ix in indexes.iter().take(3) {
            let url = format!(
                "{}?url=*.{}/*&output=json&fl=url&limit=5000",
                ix.cdx_api.trim_end_matches('/'),
                domain
            );
            tracing::debug!("commoncrawl[{}] {}", ix.id, url);
            if let Ok(r) = session.get(self.name(), &url).await {
                if let Ok(body) = r.text().await {
                    let mut h = extractor::extract(&body, domain);
                    all.append(&mut h);
                }
            }
        }
        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
