//! Source registry — owns boxed Source instances and selects the
//! enabled subset based on user options.

use std::sync::Arc;

use crate::config::{ProviderConfig, RuntimeConfig};

use super::{KeyRequirement, Source};

pub struct Registry {
    sources: Vec<Arc<dyn Source>>,
}

impl Registry {
    pub fn with_keys(provider: &ProviderConfig) -> Self {
        let mut sources: Vec<Arc<dyn Source>> = Vec::new();

        macro_rules! reg {
            ($mod:ident, $ty:ident) => {{
                let mut s = super::$mod::$ty::default();
                let keys = provider.keys_for(s.name());
                if !keys.is_empty() {
                    s.set_keys(keys);
                }
                sources.push(Arc::new(s));
            }};
        }

        // keyless
        reg!(alienvault, AlienVault);
        reg!(anubis, Anubis);
        reg!(certspotter, CertSpotter);
        reg!(commoncrawl, CommonCrawl);
        reg!(crtsh, Crtsh);
        reg!(digitorus, Digitorus);
        reg!(dnsrepo, DnsRepo);
        reg!(dnsdumpster, DnsDumpster);
        reg!(domainsproject, DomainsProject);
        reg!(hackertarget, HackerTarget);
        reg!(rapiddns, RapidDns);
        reg!(robtex, Robtex);
        reg!(sitedossier, SiteDossier);
        reg!(thc, Thc);
        reg!(threatcrowd, ThreatCrowd);
        reg!(waybackarchive, WaybackArchive);

        // keyed
        reg!(bevigil, BeVigil);
        reg!(bufferover, BufferOver);
        reg!(builtwith, BuiltWith);
        reg!(c99, C99);
        reg!(censys, Censys);
        reg!(chaos, Chaos);
        reg!(chinaz, ChinaZ);
        reg!(digitalyama, DigitalYama);
        reg!(dnsdb, DnsDb);
        reg!(driftnet, Driftnet);
        reg!(fofa, Fofa);
        reg!(fullhunt, FullHunt);
        reg!(github, GitHub);
        reg!(gitlab, GitLab);
        reg!(hudsonrock, HudsonRock);
        reg!(intelx, IntelX);
        reg!(leakix, LeakIX);
        reg!(merklemap, MerkleMap);
        reg!(netlas, Netlas);
        reg!(onyphe, Onyphe);
        reg!(profundis, Profundis);
        reg!(pugrecon, PugRecon);
        reg!(quake, Quake);
        reg!(reconeer, Reconeer);
        reg!(redhuntlabs, RedHuntLabs);
        reg!(rsecloud, RseCloud);
        reg!(securitytrails, SecurityTrails);
        reg!(shodan, Shodan);
        reg!(submd, SubMd);
        reg!(threatbook, ThreatBook);
        reg!(urlscan, UrlScan);
        reg!(virustotal, VirusTotal);
        reg!(whoisxmlapi, WhoisXmlApi);
        reg!(windvane, WindVane);
        reg!(zoomeyeapi, ZoomEyeApi);

        Self { sources }
    }

    pub fn print_list(&self) {
        let mut rows: Vec<_> = self
            .sources
            .iter()
            .map(|s| {
                let mark = match s.key_requirement() {
                    KeyRequirement::None => "  ",
                    KeyRequirement::Optional => " ~",
                    KeyRequirement::Required => " *",
                };
                let dflt = if s.is_default() { "default" } else { "       " };
                let rec = if s.has_recursive_support() {
                    "rec"
                } else {
                    "   "
                };
                (s.name().to_string(), mark, dflt, rec)
            })
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        println!("Registered sources (* = key required, ~ = key optional):");
        for (name, mark, dflt, rec) in rows {
            println!("  {mark} {name:<18}  {dflt}  {rec}");
        }
        println!("\nTotal: {} sources", self.sources.len());
    }

    pub fn select(&self, cfg: &RuntimeConfig) -> Vec<Arc<dyn Source>> {
        let allowed: Vec<&Arc<dyn Source>> = self
            .sources
            .iter()
            .filter(|s| {
                let name = s.name().to_ascii_lowercase();
                if !cfg.sources.is_empty() {
                    return cfg.sources.contains(&name);
                }
                if cfg.exclude_sources.contains(&name) {
                    return false;
                }
                if cfg.recursive {
                    return s.has_recursive_support();
                }
                if cfg.all_sources {
                    return true;
                }
                s.is_default()
            })
            .filter(|s| match s.key_requirement() {
                KeyRequirement::Required => s.has_keys(),
                _ => true,
            })
            .collect();
        allowed.into_iter().cloned().collect()
    }
}
