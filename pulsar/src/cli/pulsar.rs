use anyhow::{ensure, Result};
use clap::{ArgGroup, Parser, Subcommand};

pub const NAME: &str = "pulsar";

#[derive(Parser, Debug, Clone)]
#[clap(name = NAME)]
#[clap(about = "Pulsar cli")]
pub struct PulsarCliOpts {
    /// Specify custom api server
    #[clap(long)]
    pub api_server: Option<String>,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Modules status
    Status,

    /// Start a module
    Start { module_name: String },

    /// Restart a module
    Restart { module_name: String },

    /// Stop a module
    Stop { module_name: String },

    /// Manage module configuration
    Config(Config),

    /// Start event monitor
    Monitor(Monitor),
}

// THIS "SHIM" STRUCT IS MANDATORY
#[derive(Parser, Debug, Clone)]
#[clap(group(
    ArgGroup::new("config_variant")
        .required(true)
        .args(&["all", "module", "set"]),
))]
pub struct Config {
    /// Print configuration for all modules
    #[clap(long, short)]
    pub all: bool,

    /// Print configuration for a specified module
    #[clap(long, short)]
    pub module: Option<String>,

    /// Set/Update configuration for a specified module: syntax is 'MODULE.KEY=VALUE'
    #[clap(long, short, value_parser=parse_mc_key_value, value_name = "MODULE.KEY=VALUE")]
    pub set: Option<ModuleConfigKV>,
}

#[derive(Parser, Debug, Clone)]
pub struct ModuleConfigKV {
    pub module_name: String,
    pub key: String,
    pub value: String,
}

#[derive(Parser, Debug, Clone)]
pub struct Monitor {
    /// Show all events
    #[clap(long, default_value_t = false)]
    pub all: bool,
}

fn parse_mc_key_value(input: &str) -> Result<ModuleConfigKV> {
    // split 'module_name.config_name=config_value'
    let parts: Vec<&str> = input.split('=').filter(|s| !s.is_empty()).collect();
    ensure!(
        parts.len() == 2,
        "invalid configuration expression '{}': syntax is 'MODULE.KEY=VALUE'",
        input
    );
    let (module_and_config, value) = (parts[0], parts[1]);

    // split 'module_name.config_name'
    let parts: Vec<&str> = module_and_config
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    ensure!(
        parts.len() == 2,
        "invalid module expression '{}': syntax is 'MODULE.KEY=VALUE'",
        module_and_config
    );
    let (module_name, key) = (parts[0], parts[1]);

    Ok(ModuleConfigKV {
        module_name: module_name.to_string(),
        key: key.to_string(),
        value: value.to_string(),
    })
}
