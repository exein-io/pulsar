use serde::de::DeserializeOwned;
use thiserror::Error;

/// Raw configuration of a single module, as found in its `[module.<name>]` section.
#[derive(Debug, Clone, Default)]
pub struct ModuleConfig(toml::Table);

#[derive(Error, Debug)]
#[error("invalid configuration for module `{module}`: {error}")]
pub struct ConfigError {
    module: String,
    error: toml::de::Error,
}

impl ModuleConfig {
    /// Deserialize into the configuration type of the module owning the section,
    /// warning about the keys that type doesn't know.
    pub fn parse<T: DeserializeOwned>(self, module: &str) -> Result<T, ConfigError> {
        let (config, ignored) = self.parse_tracking_ignored(module)?;

        for key in ignored {
            log::warn!("Ignoring unknown key `{key}` in [module.{module}]");
        }

        Ok(config)
    }

    fn parse_tracking_ignored<T: DeserializeOwned>(
        self,
        module: &str,
    ) -> Result<(T, Vec<String>), ConfigError> {
        let mut ignored = Vec::new();
        let config = serde_ignored::deserialize(toml::Value::Table(self.0), |path| {
            ignored.push(path.to_string())
        })
        .map_err(|error| ConfigError {
            module: module.to_string(),
            error,
        })?;

        Ok((config, ignored))
    }
}

impl From<toml::Table> for ModuleConfig {
    fn from(table: toml::Table) -> Self {
        Self(table)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize)]
    #[serde(default)]
    struct Config {
        elf_check: bool,
        whitelist: Vec<String>,
    }

    fn parse(content: &str) -> Result<(Config, Vec<String>), ConfigError> {
        ModuleConfig::from(content.parse::<toml::Table>().unwrap())
            .parse_tracking_ignored("a-module")
    }

    #[test]
    fn known_keys_are_not_reported() {
        let (config, ignored) = parse("elf_check = true\nwhitelist = [\"/proc\"]\n").unwrap();
        assert!(config.elf_check);
        assert_eq!(config.whitelist, ["/proc"]);
        assert!(ignored.is_empty());
    }

    #[test]
    fn missing_keys_fall_back_to_defaults() {
        let (config, ignored) = parse("").unwrap();
        assert!(!config.elf_check);
        assert!(ignored.is_empty());
    }

    #[test]
    fn unknown_keys_are_reported_but_do_not_fail() {
        let (config, ignored) =
            parse("elf_check = true\nelf_chek = false\nnested = { a = 1 }\n").unwrap();
        assert!(config.elf_check);
        assert_eq!(ignored, ["elf_chek", "nested"]);
    }

    #[test]
    fn invalid_value_still_fails() {
        let err = parse("elf_check = \"yes\"").unwrap_err();
        assert!(err.to_string().contains("a-module"));
    }
}
