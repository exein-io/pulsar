use std::fmt;

use serde::de::DeserializeOwned;
use thiserror::Error;
use toml_edit::{de::from_item, Item};

#[derive(Clone, Debug)]
pub struct ConfigPath {
    items: Vec<String>,
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.items)
    }
}

#[derive(Clone, Debug)]
pub struct ConfigValue {
    pub path: ConfigPath,
    pub data: Item,
}

impl ConfigValue {
    /// Consume self and try to parse as the given type
    pub fn parse<T>(self) -> Result<T, ConfigError>
    where
        T: DeserializeOwned,
    {
        from_item(self.data).map_err(|src| ConfigError::ParsingFailure {
            src,
            type_name: std::any::type_name::<T>(),
            path: self.path.clone(),
        })
    }

    /// Traverse the configuration and produce a list of generic key-values.
    /// This works only for tables and returns None for other types.
    pub fn as_table_pairs(&self) -> Vec<(&str, String)> {
        let Some(table) = self.data.as_table() else {
            log::warn!("Config at {} is not a table", self.path);
            return Vec::new();
        };
        table
            .into_iter()
            .map(|(key, value)| (key, value.to_string()))
            .collect()
    }
}

#[derive(Error, Debug, Clone)]
pub enum ConfigError {
    #[error("parsing {path} as {type_name} failed")]
    ParsingFailure {
        path: ConfigPath,
        type_name: &'static str,
        #[source]
        src: toml_edit::de::Error,
    },
}
