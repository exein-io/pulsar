//! The OSS daemon's configuration and default components, also used by
//! builds that extend Pulsar.

use std::path::{Path, PathBuf};

use anyhow::Context;
use bpf_filtering::config::Config as FilteringConfig;
use next_bpf::loader::{DEFAULT_PIN_DIR, LoaderConfig, LogLevel, default_ring_size};
use next_core::{CoreConfig, Schema, daemon::PulsarBuilder, probe::ProcessProbe};
use next_rules_engine::RulesDetector;
use next_threat_logger::ThreatLogger;
use serde::Deserialize;

/// `pulsar.toml`.
#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub module: Modules,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub pin_dir: PathBuf,
    /// Bytes; a power of two. Default: 2 MiB per CPU, between 8 and 128 MiB.
    pub ring_size: Option<u32>,
    /// "disabled", "error" or "debug"; probe logs go to trace_pipe.
    pub bpf_log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            pin_dir: PathBuf::from(DEFAULT_PIN_DIR),
            ring_size: None,
            bpf_log_level: "error".to_string(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub struct Modules {
    #[serde(rename = "process-monitor")]
    pub process_monitor: Module<FilteringConfig>,
    #[serde(rename = "rules-engine")]
    pub rules_engine: Module<next_rules_engine::Config>,
    #[serde(rename = "threat-logger")]
    pub threat_logger: Module<next_threat_logger::Config>,
}

#[derive(Deserialize)]
pub struct Module<C> {
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(flatten)]
    pub config: C,
}

fn enabled() -> bool {
    true
}

impl<C: Default> Default for Module<C> {
    fn default() -> Self {
        Self {
            enabled: true,
            config: C::default(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn core(&self) -> anyhow::Result<CoreConfig> {
        let log_level = match self.daemon.bpf_log_level.as_str() {
            "disabled" => LogLevel::Disabled,
            "error" => LogLevel::Error,
            "debug" => LogLevel::Debug,
            other => anyhow::bail!("unknown bpf_log_level {other:?}"),
        };
        Ok(CoreConfig {
            loader: LoaderConfig {
                pin_dir: self.daemon.pin_dir.clone(),
                ring_size: self.daemon.ring_size.unwrap_or_else(default_ring_size),
                log_level,
            },
            filtering: self.module.process_monitor.config.clone(),
            ..CoreConfig::default()
        })
    }
}

/// Adds the OSS probes, detectors and reporters that `config` enables.
pub trait OssDefaults: Sized {
    fn oss_defaults(self, config: &Config) -> anyhow::Result<Self>;
}

impl<S: Schema> OssDefaults for PulsarBuilder<S> {
    fn oss_defaults(mut self, config: &Config) -> anyhow::Result<Self> {
        let modules = &config.module;
        if modules.process_monitor.enabled {
            self = self.probe(ProcessProbe);
        }
        if modules.rules_engine.enabled {
            self = self.detector(RulesDetector::<S>::new(&modules.rules_engine.config)?);
        }
        if modules.threat_logger.enabled {
            let (logger, syslog_unreachable) = ThreatLogger::new(&modules.threat_logger.config);
            if syslog_unreachable {
                log::warn!("threat-logger: syslog unreachable");
            }
            self = self.reporter(logger);
        }
        Ok(self)
    }
}
