//! Pulsar is a runtime security observability framework powered by eBPF.
//! At high level it provides two components:
//!
//! - a modular [daemon](crate::pulsard::PulsarDaemon) that should be run as a service on the machine
//!   and it's responsible for managing the state of [modules](#modules) that come with Pulsar 
//! - a [cli](crate::cli::pulsar) to interact with the daemon to do administration operations
//! 
//! Both components are embedded in a single binary application and are executed through subcommands of the
//! main application `pulsar-exec`. Example:
//! 
//! ```sh
//! # Execute the daemon
//! pulsar-exec pulsard
//! 
//! # Execute the cli
//! pulsar-exec pulsar
//! ```
//! 
//! **Note**: Simple scripts are provided in the repository for an easy access.
//!
//! ## Modules
//! 
//! Functionality is enabled through the use of Pulsar [modules](pulsar_core::pdk).
//! Modules are sub-programs that perform specific operations (e.g. monitoring filesystem access) 
//! that are loaded into Pulsar at runtime and enable the use of eBPF to power
//! most modules.
//! 
//! Internally every module has access to the shared message [bus](pulsar_core::bus)
//! and can either produce or consume [events](pulsar_core::event). It's a broadcast MPMC 
//! channel (multi-producer, multi consumer) where every subscriber will receive 
//! every message. This allows to build modular code with a clear separation of 
//! concerns.
//! 
//! Check the [example](pulsar_core::pdk#example) in the modules documentation
//! to discover how to implement a simple Pulsar module.
//! 
//! ## Feature flags
//!
//! Pulsar uses a set of [feature flags] to reduce the amount of compiled code. It
//! is possible to just enable certain features over others. By default, Pulsar
//! enable all features but allows one to disable a subset for their use case.
//! Below is a list of the available feature flags. If you are new to Pulsar it is
//! recommended that you use the default features flag which will enable all public APIs.
//!
//!
//! - `default`: Enables core and extra.
//! - `core`: Enables all the monitoring features listed below, specifically
//!           `  logger`, `process-monitor`, `network-monitor`, `syscall-monitor`
//!              and `file-system-monitor`.
//! - `extra`: Enables the rule-engine feature.
//! - `logger`: Enables the event logger to print threat events in the console.
//! - `process-monitor`: Enables a monitor on processes lifecycle and manages the list
//!                      of interesting applications. It's considered a core module and
//!                      should never be disabled.
//! - `network-monitor`: Enables a monitor on networks events: connections events and
//!                      dns events.
//! - `syscall-monitor`: Enables a monitor on syscall event, it produces an aggregated
//!                      map of syscall events with syscalls as key and relative counts
//!                      as value.
//! - `file-system-monitor`: Enables a monitor on file system events, example file open, delete, ecc.
//! - `rules-engine`: Enables the rule engine module to process events and detect threats.

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
