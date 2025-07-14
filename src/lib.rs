//! Pulsar is a runtime security observability framework powered by eBPF.
//! At high level it provides two components:
//!
//! - a modular [daemon](crate::pulsard::PulsarDaemon) that should be run as a service on the machine
//!   and it's responsible for managing the state of [modules](#modules) that come with Pulsar
//! - a [cli](crate::cli::pulsar) to interact with the daemon to do administration operations
//!
//! The two components are provided as separate binaries: `pulsard` (daemon) and `pulsar` (CLI).
//! Example:
//!
//! ```sh
//! # Execute the daemon
//! pulsard
//!
//! # Execute the cli
//! pulsar
//! ```
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
//!   `logger`, `process-monitor`, `network-monitor` and `file-system-monitor`.
//! - `extra`: Enables the rule-engine feature.
//! - `logger`: Enables the event logger to print threat events in the console.
//! - `process-monitor`: Enables a monitor on processes lifecycle and manages the list
//!   of interesting applications. It's considered a core module and
//!   should never be disabled.
//! - `network-monitor`: Enables a monitor on networks events: connections events and
//!   dns events.
//! - `file-system-monitor`: Enables a monitor on file system events, example file open, delete, ecc.
//! - `rules-engine`: Enables the rule engine module to process events and detect threats.

pub mod pulsar;
pub mod pulsard;
pub mod utils;

pub mod metadata {
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");
    pub const GIT_SHA: &str = env!("VERGEN_GIT_SHA");
}

/// Init logger. We log from info level and above, hide timestamp
/// and module path.
/// If RUST_LOG is set, we assume the user wants to debug something
/// and use env_logger default behaviour.
pub fn init_logger(override_log_level: Option<log::LevelFilter>) {
    if std::env::var_os("RUST_LOG").is_some() {
        env_logger::init();
    } else {
        let level_filter = override_log_level.unwrap_or(log::LevelFilter::Info);

        env_logger::builder().filter_level(level_filter).init();
    }
}
