use std::{
    collections::{
        HashMap,
        hash_map::{IntoIter, Iter},
    },
    fmt::{Debug, Display},
    str::FromStr,
};

use thiserror::Error;

/// Per module configuration
#[derive(Debug, Clone, Default)]
pub struct ModuleConfig {
    inner: HashMap<String, String>,
}

#[derive(Error, Debug, Clone)]
pub enum ConfigError {
    #[error("field {field} is required")]
    RequiredValue { field: String },
    #[error("{value} is not a valid value for field {field}: {err}")]
    InvalidValue {
        field: String,
        value: String,
        err: String,
    },
}

impl ModuleConfig {
    /// Inserts a new configuration value.
    pub fn insert(&mut self, key: String, value: String) -> Option<String> {
        self.inner.insert(key, value)
    }

    /// Returns an option of raw configuration value.
    pub fn get_raw(&self, config_name: &str) -> Option<&str> {
        self.inner.get(config_name).map(String::as_str)
    }

    /// Returns a typed configuration value.
    pub fn required<T>(&self, config_name: &str) -> Result<T, ConfigError>
    where
        T: FromStr,
        <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
    {
        match self.inner.get(config_name) {
            None => Err(ConfigError::RequiredValue {
                field: config_name.to_string(),
            }),
            Some(value) => parse(value, config_name),
        }
    }

    /// Returns an optional typed configuration value.
    pub fn optional<T>(&self, config_name: &str) -> Result<Option<T>, ConfigError>
    where
        T: FromStr,
        <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
    {
        self.inner
            .get(config_name)
            .map(|value| parse(value, config_name))
            .transpose()
    }

    /// Return a comma separed list of values. Return empty vector if field is missing.
    pub fn get_list<T>(&self, config_name: &str) -> Result<Vec<T>, ConfigError>
    where
        T: FromStr,
        <T as FromStr>::Err: Display,
    {
        self.inner
            .get(config_name)
            .iter()
            .flat_map(|config| config.split(','))
            .filter(|item| !item.is_empty())
            .map(|item| parse(item.trim(), config_name))
            .collect()
    }

    /// Return a comma separed list of values. Return default vector if field is missing.
    pub fn get_list_with_default<T>(
        &self,
        config_name: &str,
        default: Vec<T>,
    ) -> Result<Vec<T>, ConfigError>
    where
        T: FromStr,
        <T as FromStr>::Err: std::error::Error + Send + Sync + 'static,
    {
        if self.inner.contains_key(config_name) {
            self.get_list(config_name)
        } else {
            Ok(default)
        }
    }

    /// Return an Iter to the underlying HashMap
    pub fn iter(&self) -> Iter<'_, String, String> {
        self.inner.iter()
    }

    /// Return an IntoIter to the underlying HashMap
    #[allow(clippy::should_implement_trait)]
    pub fn into_iter(self) -> IntoIter<String, String> {
        self.inner.into_iter()
    }
}

fn parse<T>(value: &str, config_name: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    <T as FromStr>::Err: Display,
{
    T::from_str(value).map_err(|err| ConfigError::InvalidValue {
        field: config_name.to_string(),
        value: value.to_string(),
        err: err.to_string(),
    })
}
