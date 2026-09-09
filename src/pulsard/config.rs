use std::{collections::HashMap, fs::File, path::PathBuf};

use anyhow::{Context, Result, bail};
use pulsar_core::pdk::ModuleConfig;

const DEFAULT_CONFIG_FILE: &str = "/var/lib/pulsar/pulsar.ini";

/// Global Pulsar configuration, parsed from an `INI` file at startup.
#[derive(Debug, Clone)]
pub struct PulsarConfig {
    configs: HashMap<String, ModuleConfig>,
}

impl PulsarConfig {
    /// Construct a new [`PulsarConfig`] using the default file, creating it if missing.
    pub fn new() -> Result<Self> {
        let config_file = PathBuf::from(DEFAULT_CONFIG_FILE);
        if !config_file.exists() {
            let prefix = config_file.parent().unwrap(); // Unwrap if / is passed
            std::fs::create_dir_all(prefix).unwrap();
            File::create(&config_file)?;
        }
        Self::from_config_file(config_file)
    }

    /// Construct a new [`PulsarConfig`] using a custom file.
    pub fn with_custom_file(config_file: &str) -> Result<Self> {
        let config_file = PathBuf::from(config_file);
        if !config_file.exists() {
            bail!("Configuration file {} not found", config_file.display());
        }
        Self::from_config_file(config_file)
    }

    fn from_config_file(config_file: PathBuf) -> Result<Self> {
        let mut configs: HashMap<String, ModuleConfig> = HashMap::new();

        let conf = ini::Ini::load_from_file(&config_file)
            .with_context(|| format!("Error loading configuration from {config_file:?}"))?;

        for (section, prop) in &conf {
            if let Some(section) = section {
                let mod_config = configs.entry(section.to_string()).or_default();
                for (key, value) in prop.iter() {
                    log::debug!("{}.{}={}", section, key, value);
                    mod_config.insert(key.to_string(), value.to_string());
                }
            }
        }

        Ok(Self { configs })
    }

    /// Get the configuration of a module. Modules without a section get an empty one.
    pub fn get_module_config(&self, module: &str) -> ModuleConfig {
        self.configs.get(module).cloned().unwrap_or_default()
    }
}
