use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;

use crate::extractor;
use crate::session::Session;

use super::{empty_stream, err_stream, ok_stream, KeyRequirement, Source, SubStream};

static CSRF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"csrfmiddlewaretoken" value="([^"]+)""#)
        .expect("dnsdumpster CSRF regex is valid")
});

#[derive(Default)]
pub struct DnsDumpster;

#[async_trait::async_trait]
impl Source for DnsDumpster {
    fn name(&self) -> &'static str {
        "dnsdumpster"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        // Step 1: GET the homepage to obtain a CSRF token.
        session.throttle(self.name()).await;
        let get_resp = match session
            .client()
            .get("https://dnsdumpster.com/")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return err_stream(anyhow::anyhow!("dnsdumpster GET failed: {e}")),
        };

        let get_body = get_resp.text().await.unwrap_or_default();

        let token = match CSRF_RE.captures(&get_body).and_then(|c| c.get(1)) {
            Some(m) => m.as_str().to_string(),
            None => return empty_stream(),
        };

        // Step 2: POST with CSRF token and target domain.
        session.throttle(self.name()).await;
        let post_resp = match session
            .client()
            .post("https://dnsdumpster.com/")
            .header("Referer", "https://dnsdumpster.com/")
            .header("Cookie", format!("csrftoken={token}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(format!(
                "csrfmiddlewaretoken={token}&targetip={domain}&user=free"
            ))
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return err_stream(anyhow::anyhow!("dnsdumpster POST failed: {e}")),
        };

        let text = post_resp.text().await.unwrap_or_default();
        let mut hosts = extractor::extract(&text, domain);
        hosts.sort();
        hosts.dedup();
        session.record_results(self.name(), hosts.len());
        ok_stream(hosts)
    }
}
