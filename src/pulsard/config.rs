use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use bpf_common::program::PERF_PAGES_DEFAULT;
use pulsar_core::pdk::{ConfigError, ModuleConfig};
use serde::{Deserialize, de::DeserializeOwned};

const DEFAULT_CONFIG_FILE: &str = "/var/lib/pulsar/pulsar.toml";
const CONFIG_TEMPLATE: &str = include_str!("pulsar.toml.template");

/// Global Pulsar configuration, parsed from a `TOML` file at startup.
#[derive(Debug, Deserialize)]
pub struct PulsarConfig {
    /// Settings of the agent itself.
    #[serde(default)]
    pub pulsar: GeneralConfig,
    /// Module sections, keyed by module name.
    #[serde(default)]
    module: HashMap<String, ModuleSection>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Size of the perf event buffer shared with the eBPF probes, in pages.
    pub perf_pages: usize,
    /// File the kernel BTF is read from, instead of the running kernel one.
    pub btf_path: Option<PathBuf>,
    /// Unix socket the API server listens on.
    pub api_socket_path: Option<String>,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            perf_pages: PERF_PAGES_DEFAULT,
            btf_path: None,
            api_socket_path: None,
        }
    }
}

/// A `[module.<name>]` section: the flag shared by every module plus the module
/// specific keys, left unparsed for the module to claim.
#[derive(Debug, Default, Deserialize)]
pub struct ModuleSection {
    /// Whether the module is started with the daemon.
    pub enabled: Option<bool>,
    #[serde(flatten)]
    config: toml::Table,
}

impl ModuleSection {
    /// Deserialize the module specific keys into the module configuration type.
    pub fn parse_config<T: DeserializeOwned>(self, module: &str) -> Result<T, ConfigError> {
        ModuleConfig::from(self.config).parse(module)
    }
}

impl PulsarConfig {
    /// Construct a new [`PulsarConfig`] using the default file, writing a
    /// commented template if it doesn't exist yet.
    pub fn new() -> Result<Self> {
        let config_file = PathBuf::from(DEFAULT_CONFIG_FILE);
        if !config_file.exists() {
            let prefix = config_file.parent().unwrap(); // Unwrap if / is passed
            fs::create_dir_all(prefix)
                .with_context(|| format!("Error creating {}", prefix.display()))?;
            fs::write(&config_file, CONFIG_TEMPLATE)
                .with_context(|| format!("Error writing {}", config_file.display()))?;
        }
        Self::from_file(&config_file)
    }

    /// Construct a new [`PulsarConfig`] using a custom file.
    pub fn with_custom_file(config_file: &str) -> Result<Self> {
        let config_file = Path::new(config_file);
        if !config_file.exists() {
            bail!("Configuration file {} not found", config_file.display());
        }
        Self::from_file(config_file)
    }

    fn from_file(config_file: &Path) -> Result<Self> {
        let content = fs::read_to_string(config_file)
            .with_context(|| format!("Error reading {}", config_file.display()))?;

        let (config, ignored) = Self::parse_str(&content)
            .with_context(|| format!("Error parsing {}", config_file.display()))?;

        for key in ignored {
            log::warn!("Ignoring unknown key `{key}` in {}", config_file.display());
        }

        Ok(config)
    }

    /// Parse the file content, collecting the keys no field claimed. Keys of a
    /// `[module.<name>]` section are never collected here: they are captured by
    /// [`ModuleSection`] and checked once the module claims them.
    fn parse_str(content: &str) -> Result<(Self, Vec<String>), toml::de::Error> {
        let mut ignored = Vec::new();
        let config = serde_ignored::deserialize(toml::Deserializer::parse(content)?, |path| {
            ignored.push(path.to_string())
        })?;

        Ok((config, ignored))
    }

    /// Take the section of a module, leaving behind only the unclaimed ones.
    pub fn take_module(&mut self, module: &str) -> Option<ModuleSection> {
        self.module.remove(module)
    }

    /// Warn about the sections no module has claimed.
    pub fn warn_unclaimed(&self) {
        for module in self.module.keys() {
            log::warn!(
                "Ignoring configuration for `{module}`: no such module is loaded. \
                 It may be misspelled or built out of this binary."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> PulsarConfig {
        PulsarConfig::parse_str(content).unwrap().0
    }

    fn ignored(content: &str) -> Vec<String> {
        PulsarConfig::parse_str(content).unwrap().1
    }

    #[test]
    fn template_parses_to_defaults() {
        let config = parse(CONFIG_TEMPLATE);
        assert_eq!(config.pulsar.perf_pages, PERF_PAGES_DEFAULT);
        assert!(config.pulsar.btf_path.is_none());
        assert!(config.module.values().all(|s| s.enabled.is_none()));
        assert!(ignored(CONFIG_TEMPLATE).is_empty());
    }

    #[test]
    fn empty_file_parses() {
        let config = parse("");
        assert_eq!(config.pulsar.perf_pages, PERF_PAGES_DEFAULT);
        assert!(config.module.is_empty());
    }

    #[test]
    fn module_keys_are_kept_apart_from_enabled() {
        let mut config = parse(
            r#"
            [module.file-system-monitor]
            enabled = true
            elf_check = true
            elf_check_whitelist = ["/proc"]
            "#,
        );

        let section = config.take_module("file-system-monitor").unwrap();
        assert_eq!(section.enabled, Some(true));
        assert_eq!(section.config.len(), 2);
        assert!(!section.config.contains_key("enabled"));
    }

    #[test]
    fn taking_a_module_leaves_the_others_unclaimed() {
        let mut config = parse("[module.known]\n[module.typo]\n");
        assert!(config.take_module("known").is_some());
        assert!(config.take_module("absent").is_none());
        assert_eq!(config.module.keys().collect::<Vec<_>>(), ["typo"]);
    }

    #[test]
    fn unknown_top_level_keys_are_reported() {
        assert_eq!(ignored("[modul.file-system-monitor]"), ["modul"]);
        assert_eq!(ignored("perf_pages = 64"), ["perf_pages"]);
    }

    #[test]
    fn unknown_general_key_is_reported() {
        assert_eq!(ignored("[pulsar]\nperf_page = 64"), ["pulsar.perf_page"]);
    }

    #[test]
    fn module_keys_are_left_to_the_module() {
        assert!(ignored("[module.a]\nanything = 1\n").is_empty());
    }

    #[test]
    fn invalid_value_still_fails() {
        assert!(PulsarConfig::parse_str("[pulsar]\nperf_pages = \"lots\"").is_err());
    }
}
