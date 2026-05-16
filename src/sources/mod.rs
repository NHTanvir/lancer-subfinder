//! Passive subdomain sources. Each module under `sources::<name>` implements
//! the [`Source`] trait and is registered in [`registry::Registry`].

pub mod registry;

// keyless / free
pub mod alienvault;
pub mod anubis;
pub mod certspotter;
pub mod commoncrawl;
pub mod crtsh;
pub mod digitorus;
pub mod dnsrepo;
pub mod dnsdumpster;
pub mod domainsproject;
pub mod hackertarget;
pub mod rapiddns;
pub mod robtex;
pub mod sitedossier;
pub mod thc;
pub mod threatcrowd;
pub mod waybackarchive;

// keyed
pub mod bevigil;
pub mod bufferover;
pub mod builtwith;
pub mod c99;
pub mod censys;
pub mod chaos;
pub mod chinaz;
pub mod digitalyama;
pub mod dnsdb;
pub mod driftnet;
pub mod fofa;
pub mod fullhunt;
pub mod github;
pub mod gitlab;
pub mod hudsonrock;
pub mod intelx;
pub mod leakix;
pub mod merklemap;
pub mod netlas;
pub mod onyphe;
pub mod profundis;
pub mod pugrecon;
pub mod quake;
pub mod reconeer;
pub mod redhuntlabs;
pub mod rsecloud;
pub mod securitytrails;
pub mod shodan;
pub mod submd;
pub mod threatbook;
pub mod urlscan;
pub mod virustotal;
pub mod whoisxmlapi;
pub mod windvane;
pub mod zoomeyeapi;

use std::pin::Pin;
use std::sync::Arc;

use futures::Stream;

pub type SubStream =
    Pin<Box<dyn Stream<Item = anyhow::Result<String>> + Send + 'static>>;

/// What kind of key a source needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRequirement {
    None,
    Optional,
    Required,
}

#[async_trait::async_trait]
pub trait Source: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn is_default(&self) -> bool {
        true
    }
    fn has_recursive_support(&self) -> bool {
        false
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn set_keys(&mut self, _keys: Vec<String>) {}
    fn has_keys(&self) -> bool {
        true
    }

    async fn enumerate(
        &self,
        domain: &str,
        session: Arc<crate::session::Session>,
    ) -> SubStream;
}

// --- helpers ---

/// Pick the next API key in a round-robin fashion (thread-safe).
pub fn next_key(keys: &[String], counter: &std::sync::atomic::AtomicUsize) -> Option<String> {
    if keys.is_empty() {
        return None;
    }
    let i = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Some(keys[i % keys.len()].clone())
}

/// Convert an iterator of hosts into a SubStream of Ok(host).
pub fn ok_stream(items: Vec<String>) -> SubStream {
    Box::pin(futures::stream::iter(items.into_iter().map(Ok)))
}

/// Stream of a single error.
pub fn err_stream(e: anyhow::Error) -> SubStream {
    Box::pin(futures::stream::iter(std::iter::once(Err(e))))
}

/// Empty stream.
pub fn empty_stream() -> SubStream {
    Box::pin(futures::stream::iter(Vec::<anyhow::Result<String>>::new()))
}
