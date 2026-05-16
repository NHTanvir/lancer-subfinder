//! Per-source statistics, surfaced via --stats.

use std::time::Duration;

use dashmap::DashMap;

#[derive(Debug, Clone, Default)]
pub struct SourceStat {
    pub requests: usize,
    pub errors: usize,
    pub results: usize,
    pub elapsed: Duration,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub per_source: std::collections::HashMap<String, SourceStat>,
}

impl Stats {
    pub fn from_map(map: &DashMap<String, SourceStat>) -> Self {
        let mut per = std::collections::HashMap::new();
        for r in map.iter() {
            per.insert(r.key().clone(), r.value().clone());
        }
        Self { per_source: per }
    }

    pub fn merge(&mut self, other: &Stats) {
        for (k, v) in &other.per_source {
            let e = self.per_source.entry(k.clone()).or_default();
            e.requests += v.requests;
            e.errors += v.errors;
            e.results += v.results;
            e.elapsed += v.elapsed;
        }
    }

    pub fn print(&self) {
        let mut keys: Vec<&String> = self.per_source.keys().collect();
        keys.sort();
        eprintln!();
        eprintln!(
            "{:<18}  {:>6}  {:>6}  {:>7}  {:>9}",
            "source", "reqs", "errs", "results", "time(ms)"
        );
        eprintln!("{}", "-".repeat(54));
        for k in keys {
            let s = &self.per_source[k];
            eprintln!(
                "{:<18}  {:>6}  {:>6}  {:>7}  {:>9}",
                k,
                s.requests,
                s.errors,
                s.results,
                s.elapsed.as_millis(),
            );
        }
    }
}
