use std::{
    collections::HashMap,
    fs::File,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{bail, Context, Result};
use pulsar_core::pdk::{ConfigPath, ConfigValue};
use serde::Serialize;
use tokio::sync::watch;
use toml_edit::{de::from_item, Document, Item};

const DEFAULT_CONFIG_FILE: &str = "/var/lib/pulsar/pulsar.toml";

/// Global Pulsar configuration manager. Contains configuration for all the modules.
///
/// It is backed by an `INI` file from which parses the data on its creation.
#[derive(Debug, Clone)]
pub(crate) struct PulsarConfig {
    inner: Arc<Mutex<PulsarConfigInternal>>,
}

#[derive(Debug)]
struct PulsarConfigInternal {
    config_file: PathBuf,
    config: Document,
    watched_configs: HashMap<String, watch::Sender<ConfigValue>>,
}

impl PulsarConfig {
    /// Construct a new [`PulsarConfig`] using the default file.
    pub(crate) async fn new() -> Result<Self> {
        let config_file = PathBuf::from(DEFAULT_CONFIG_FILE);
        if !config_file.exists() {
            let prefix = config_file.parent().unwrap(); // Unwrap if / is passed
            std::fs::create_dir_all(prefix).unwrap();
            File::create(&config_file)?;
        }
        Self::from_config_file(config_file).await
    }

    /// Construct a new [`PulsarConfig`] using a custom file.
    pub(crate) async fn with_custom_file(config_file: &str) -> Result<Self> {
        let config_file = PathBuf::from(config_file);
        if !config_file.exists() {
            bail!("Configuration file {} not found", config_file.display());
        }
        Self::from_config_file(config_file).await
    }

    async fn from_config_file(config_file: PathBuf) -> Result<Self> {
        let config = tokio::fs::read_to_string(&config_file)
            .await
            .with_context(|| format!("Error reading configuration from {:?}", config_file))?
            .parse()
            .with_context(|| format!("Error parsing configuration from {:?}", config_file))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(PulsarConfigInternal {
                config_file,
                config,
                watched_configs: HashMap::new(),
            })),
        })
    }

    /// Get [`watch::Receiver`] of a module configuration. This is intended to be used in modules.
    pub(crate) fn get_watched_module_config(&self, module: &str) -> watch::Receiver<ConfigValue> {
        let mut inner = self.inner.lock().unwrap();
        // get or create a watcher for the given module
        let rx = match inner.watched_configs.get(module) {
            Some(tx) => tx.subscribe(),
            None => {
                let inner_config = inner
                    .config
                    .get(module)
                    .map(Clone::clone)
                    .unwrap_or_else(|| Item::Table(Default::default()));
                let (tx, rx) = watch::channel(ConfigValue {
                    path: ConfigPath {
                        items: vec![module.to_string()],
                    },
                    data: inner_config,
                });
                inner.watched_configs.insert(module.to_string(), tx);
                rx
            }
        };
        // Cleanup unused watchers
        inner.watched_configs.retain(|_key, tx| !tx.is_closed());
        rx
    }

    /// Get module configuration. This is intended to be used when a single access is enought.
    pub(crate) fn get_module_config(&self, module: &str) -> ConfigValue {
        self.inner
            .lock()
            .unwrap()
            .config
            .get(module)
            .map(Clone::clone)
            .unwrap_or_else(|| ConfigValue::Table(Default::default()))
    }

    /// Try to parse as T a subset of the configuration.
    /// Returns None if nothing is found at the given path.
    /// Returns Some(Ok(T)) on deserialization success
    /// Returns Some(Err(_)) on deserialization failure
    pub(crate) fn get_config<T>(&self, path: &[&str]) -> Option<Result<T>>
    where
        T: serde::de::DeserializeOwned,
    {
        let ctx = self.inner.lock().unwrap();
        let mut config = ctx.config.as_item();
        for item in path {
            config = config.get(item)?;
        }
        Some(from_item(config.clone()).with_context(|| format!("Error parsing value {:?}", path)))
    }

    /// Get all configurations. This is intended to be used when a single access is enought.
    pub(crate) fn get_configs(&self) -> ConfigValue {
        self.inner.lock().unwrap().config.clone()
    }

    /// Update module configuration. It takes a key and value.
    pub(crate) async fn update_config<T>(&self, path: &[&str], value: T) -> Result<()>
    where
        T: Serialize,
    {
        // let inner = self.inner.lock().unwrap();

        // parse again the toml file, this time preserving whitespace and comments
        //let mut document: Document = parse_config(&update_ctx.config_file).await?;
        //{
        //    path.iter()
        //        .fold(&mut document, |item, document| document[item]) = value;
        //}

        // if let Some(module_config) = update_ctx.config.get(module) {
        //     // use module_config
        // } else {

        //     .get_mut(module)
        //     .with_context(|| format!("Module {} not found", module))?;
        // }

        // // Take the old value and store to temporary variable
        // let mut mod_config = sender_mod_config.borrow().clone();

        // // Update the temporary variable
        // mod_config.insert(key.to_string(), value.to_string());

        // // Send the updated value to the watch channel
        // sender_mod_config.send_replace(mod_config);
        todo!()
    }
}

async fn parse_config<T>(config_file: &PathBuf) -> Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    tokio::fs::read_to_string(&config_file)
        .await
        .with_context(|| format!("Error reading configuration from {:?}", config_file))?
        .parse()
        .with_context(|| format!("Error parsing configuration from {:?}", config_file))
}

///// Open configuration ini file, update the given config and save it to disk
//fn update_file_config(config_file: &PathBuf, updates: &[ModuleConfigUpdate]) -> Result<()> {
//    let mut conf = ini::Ini::load_from_file(config_file)
//        .with_context(|| format!("Error loading configuration from {:?}", &config_file))?;
//
//    for ModuleConfigUpdate { path, value } in updates {
//        conf.with_section(Some(*module)).set(*key, *value);
//        log::debug!("Changing configuration {}.{}={}", module, key, value);
//    }
//
//    conf.write_to_file(config_file)
//        .with_context(|| format!("Error writing to {:?}", &config_file))?;
//
//    Ok(())
//}
