use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, bail};
use pulsar_core::pdk::ModuleConfig;
use tokio::sync::watch;

const DEFAULT_CONFIG_FILE: &str = "/var/lib/pulsar/pulsar.ini";

/// Global Pulsar configuration manager. Contains configuration for all the modules.
///
/// It is backed by an `INI` file from which parses the data on its creation.
#[derive(Debug, Clone)]
pub struct PulsarConfig {
    inner: Arc<Mutex<PulsarConfigInternal>>,
}

#[derive(Debug)]
struct PulsarConfigInternal {
    config_file: PathBuf,
    configs: HashMap<String, watch::Sender<ModuleConfig>>,
}

impl PulsarConfig {
    /// Construct a new [`PulsarConfig`] using the default file.
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

        let configs: HashMap<_, _> = configs
            .into_iter()
            .map(|(module_name, cfg)| {
                let (tx, _) = watch::channel(cfg);
                (module_name, tx)
            })
            .collect();

        Ok(Self {
            inner: Arc::new(Mutex::new(PulsarConfigInternal {
                config_file,
                configs,
            })),
        })
    }

    /// Get [`watch::Receiver`] of a module configuration. This is intended to be used in modules.
    pub fn get_watched_module_config(&self, module: &str) -> watch::Receiver<ModuleConfig> {
        self.inner
            .lock()
            .unwrap()
            .configs
            .entry(module.to_string())
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ModuleConfig::default());
                tx
            })
            .subscribe()
    }

    /// Get module configuration. This is intended to be used when a single access is enough.
    pub fn get_module_config(&self, module: &str) -> Option<ModuleConfig> {
        self.inner
            .lock()
            .unwrap()
            .configs
            .get(module)
            .map(|watch_sender| watch_sender.borrow().clone())
    }

    /// Get all configurations. This is intended to be used when a single access is enough.
    pub fn get_configs(&self) -> Vec<(String, ModuleConfig)> {
        self.inner
            .lock()
            .unwrap()
            .configs
            .iter()
            .map(|(module, watch_sender)| (module.clone(), watch_sender.borrow().clone()))
            .collect()
    }

    /// Update module configuration. It takes a key and value.
    pub fn update_config(&self, module: &str, key: &str, value: &str) -> Result<()> {
        let mut update_ctx = self.inner.lock().unwrap();

        // Get or create the watch sender
        let sender_mod_config = update_ctx
            .configs
            .entry(module.to_string())
            .or_insert_with(|| {
                let (tx, _) = watch::channel(ModuleConfig::default());
                tx
            });

        // Take the old value and store to temporary variable
        let mut mod_config = sender_mod_config.borrow().clone();

        // Update the temporary variable
        mod_config.insert(key.to_string(), value.to_string());

        // Send the updated value to the watch channel
        sender_mod_config.send_replace(mod_config);

        let shim = vec![ModuleConfigUpdate { module, key, value }];

        update_file_config(&update_ctx.config_file, &shim)?;

        Ok(())
    }
}

/// Used as helper struct to update multiple configuration at same time
struct ModuleConfigUpdate<'a> {
    module: &'a str,
    key: &'a str,
    value: &'a str,
}

/// Open configuration ini file, update the given config and save it to disk
fn update_file_config(config_file: &PathBuf, updates: &[ModuleConfigUpdate]) -> Result<()> {
    let mut conf = ini::Ini::load_from_file(config_file)
        .with_context(|| format!("Error loading configuration from {:?}", &config_file))?;

    for ModuleConfigUpdate { module, key, value } in updates {
        conf.with_section(Some(*module)).set(*key, *value);
        log::debug!("Changing configuration {}.{}={}", module, key, value);
    }

    conf.write_to_file(config_file)
        .with_context(|| format!("Error writing to {:?}", &config_file))?;

    Ok(())
}
