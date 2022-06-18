use std::env;

use anyhow::Result;
use lazy_static::lazy_static;

pub use pulsar_core::pdk::TaskLauncher;

use cli::PulsarExecOpts;

pub mod cli;
pub mod pulsar;
pub mod pulsard;

pub(crate) fn version() -> &'static str {
    #[cfg(debug_assertions)]
    lazy_static! {
        static ref VERSION: String = format!("{}+dev", env!("CARGO_PKG_VERSION"));
    }

    #[cfg(not(debug_assertions))]
    lazy_static! {
        static ref VERSION: String = env!("CARGO_PKG_VERSION").to_string();
    }
    &VERSION
}

pub fn modules() -> Vec<Box<dyn TaskLauncher>> {
    [
        #[cfg(feature = "process-monitor")]
        process_monitor::pulsar::module(),
        #[cfg(feature = "file-system-monitor")]
        file_system_monitor::pulsar::module(),
        #[cfg(feature = "syscall-monitor")]
        syscall_monitor::pulsar::module(),
        #[cfg(feature = "network-monitor")]
        network_monitor::pulsar::module(),
        #[cfg(feature = "logger")]
        logger::module(),
        #[cfg(feature = "rules-engine")]
        rules_engine::module(),
    ]
    .into_iter()
    .map(|x| Box::new(x) as Box<dyn TaskLauncher>)
    .collect()
}

/// Init logger. We log from info level and above, hide timestamp
/// and module path.
/// If RUST_LOG is set, we assume the user wants to debug something
/// and use env_logger default behaviour.
pub fn init_logger(override_log_level: log::Level) {
    if std::env::var_os("RUST_LOG").is_some() {
        env_logger::init();
    } else {
        let default_level = log::Level::Info;
        let level = if override_log_level > default_level {
            override_log_level
        } else {
            default_level
        };
        env_logger::builder()
            .format_timestamp(None)
            .format_module_path(false)
            .filter_level(level.to_level_filter())
            .init();
    }
}

/// Main pulsar entrypoint
pub async fn run_pulsar_exec(
    options: &PulsarExecOpts,
    modules: Vec<Box<dyn TaskLauncher>>,
) -> Result<()> {
    match &options.mode {
        cli::Mode::PulsarCli(options) => pulsar::pulsar_cli_run(options).await,
        cli::Mode::PulsarDaemon(options) => pulsard::pulsar_daemon_run(options, modules).await,
    }
}
