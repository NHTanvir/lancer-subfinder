//! Output writers — stdout, plain-text file, JSON-lines, CSV, per-domain dir.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::engine::EnumerationResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Txt,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn from_flags(json: bool, csv: bool) -> Self {
        if json {
            Self::Json
        } else if csv {
            Self::Csv
        } else {
            Self::Txt
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Json => "jsonl",
            Self::Csv => "csv",
        }
    }
}

#[derive(Serialize)]
struct JsonLine<'a> {
    host: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sources: Vec<String>,
    domain: &'a str,
}

pub struct OutputWriter {
    format: OutputFormat,
    collect_sources: bool,
    main_file: Option<BufWriter<File>>,
    per_domain_dir: Option<PathBuf>,
    stdout: bool,
}

impl OutputWriter {
    pub fn new(
        main: &Option<PathBuf>,
        per_domain: Option<&Path>,
        format: OutputFormat,
        collect_sources: bool,
    ) -> anyhow::Result<Self> {
        let main_file = match main {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    if !parent.as_os_str().is_empty() {
                        fs::create_dir_all(parent)?;
                    }
                }
                Some(BufWriter::new(File::create(p)?))
            }
            None => None,
        };
        if let Some(d) = per_domain {
            fs::create_dir_all(d)?;
        }
        Ok(Self {
            format,
            collect_sources,
            main_file,
            per_domain_dir: per_domain.map(|p| p.to_path_buf()),
            stdout: true,
        })
    }

    pub fn write_result(
        &mut self,
        domain: &str,
        res: &EnumerationResult,
        include_ip: bool,
    ) -> anyhow::Result<()> {
        let mut per_domain = match &self.per_domain_dir {
            Some(d) => Some(BufWriter::new(File::create(d.join(format!(
                "{domain}.{}",
                self.format.extension()
            )))?)),
            None => None,
        };
        for hit in &res.subdomains {
            let line = self.format_line(domain, hit, include_ip);
            if self.stdout {
                println!("{line}");
            }
            if let Some(f) = &mut self.main_file {
                writeln!(f, "{line}")?;
            }
            if let Some(f) = &mut per_domain {
                writeln!(f, "{line}")?;
            }
        }
        if let Some(mut f) = per_domain {
            f.flush()?;
        }
        Ok(())
    }

    fn format_line(&self, domain: &str, hit: &crate::engine::SubdomainHit, include_ip: bool) -> String {
        match self.format {
            OutputFormat::Txt => {
                if include_ip {
                    match &hit.ip {
                        Some(ip) => format!("{}:{ip}", hit.host),
                        None => hit.host.clone(),
                    }
                } else {
                    hit.host.clone()
                }
            }
            OutputFormat::Json => {
                let line = JsonLine {
                    host: &hit.host,
                    ip: hit.ip.map(|x| x.to_string()),
                    sources: if self.collect_sources {
                        hit.sources.clone()
                    } else {
                        Vec::new()
                    },
                    domain,
                };
                serde_json::to_string(&line).unwrap_or_default()
            }
            OutputFormat::Csv => {
                let srcs = if self.collect_sources {
                    hit.sources.join("|")
                } else {
                    String::new()
                };
                let ip = hit.ip.map(|x| x.to_string()).unwrap_or_default();
                csv_row(&[&hit.host, &ip, &srcs, domain])
            }
        }
    }

    pub fn finalize(&mut self) -> anyhow::Result<()> {
        if let Some(f) = &mut self.main_file {
            f.flush()?;
        }
        Ok(())
    }
}

fn csv_row(cols: &[&str]) -> String {
    cols.iter()
        .map(|c| {
            if c.contains([',', '"', '\n']) {
                format!("\"{}\"", c.replace('"', "\"\""))
            } else {
                (*c).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
