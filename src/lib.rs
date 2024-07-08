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
//!           `  logger`, `process-monitor`, `network-monitor` and `file-system-monitor`.
//! - `extra`: Enables the rule-engine feature.
//! - `logger`: Enables the event logger to print threat events in the console.
//! - `process-monitor`: Enables a monitor on processes lifecycle and manages the list
//!                      of interesting applications. It's considered a core module and
//!                      should never be disabled.
//! - `network-monitor`: Enables a monitor on networks events: connections events and
//!                      dns events.
//! - `file-system-monitor`: Enables a monitor on file system events, example file open, delete, ecc.
//! - `rules-engine`: Enables the rule engine module to process events and detect threats.

use std::env;

use anyhow::Result;
use pulsard::PulsarDaemonStarter;
use std::sync::OnceLock;

use cli::PulsarExecOpts;

pub mod cli;
pub mod pulsar;
pub mod pulsard;

pub(crate) fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    #[cfg(debug_assertions)]
    let v = VERSION.get_or_init(|| format!("{}+dev", env!("CARGO_PKG_VERSION")));

    #[cfg(not(debug_assertions))]
    let v = VERSION.get_or_init(|| env!("CARGO_PKG_VERSION").to_string());

    v
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
            .filter_level(level.to_level_filter())
            .init();
    }
}

/// Main pulsar entrypoint
pub async fn run_pulsar_exec(options: &PulsarExecOpts) -> Result<()> {
    match &options.mode {
        cli::Mode::PulsarCli(options) => pulsar::pulsar_cli_run(options).await,
        cli::Mode::PulsarDaemon(options) => pulsard::pulsar_daemon_run(options, |_| Ok(())).await,
    }
}

/// Customizable pulsar entrypoint
pub async fn run_pulsar_exec_custom(
    options: &PulsarExecOpts,
    customize_starter: impl FnOnce(&mut PulsarDaemonStarter) -> Result<()>,
) -> Result<()> {
    match &options.mode {
        cli::Mode::PulsarCli(options) => pulsar::pulsar_cli_run(options).await,
        cli::Mode::PulsarDaemon(options) => {
            pulsard::pulsar_daemon_run(options, customize_starter).await
        }
    }
}
