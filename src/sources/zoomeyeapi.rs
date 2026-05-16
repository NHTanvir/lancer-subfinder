use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct ZoomEyeApi {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    list: Option<Vec<Item>>,
    total: Option<i32>,
}
#[derive(Deserialize)]
struct Item {
    name: Option<String>,
}

#[async_trait::async_trait]
impl Source for ZoomEyeApi {
    fn name(&self) -> &'static str {
        "zoomeyeapi"
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
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };
        let mut out = Vec::new();
        for page in 1..=10 {
            let url = format!("https://api.zoomeye.org/domain/search?q={domain}&page={page}&type=1");
            let resp = match session
                .req(
                    self.name(),
                    reqwest::Method::GET,
                    &url,
                    None,
                    &[("API-KEY", key.clone())],
                )
                .await
            {
                Ok(r) => r,
                Err(_) => break,
            };
            if !resp.status().is_success() {
                break;
            }
            let parsed: Resp = match resp.json().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let list = parsed.list.unwrap_or_default();
            if list.is_empty() {
                break;
            }
            for i in list {
                if let Some(n) = i.name {
                    let h = n.trim().to_ascii_lowercase();
                    if crate::extractor::is_subdomain(&h, domain) {
                        out.push(h);
                    }
                }
            }
            if let Some(t) = parsed.total {
                if (page as i32) * 30 >= t {
                    break;
                }
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
