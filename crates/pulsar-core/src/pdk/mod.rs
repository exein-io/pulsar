//! This module includes all the necessary to build module for Pulsar
//!
//! A module should expose a function that returns a [`PulsarModule`].
//! This struct consists of basic module informations:
//! - the module name
//! - additional details in [`ModuleDetails`] struct
//!
//! and a [function](module::ModuleStartFn) to initialize the task of the module.
//!
//! This functions is the `main` function of the module and must return an implementation of [`PulsarModuleTask`].
//! The concrete type must implement an handler fot [`ShutdownSignal`] if some parts of the task need a graceful
//! shutdown or if the task have some asynchronous jobs running.
//!
//! The [`ModuleContext`] is the entrypoint to access all the functions available to the module. It provides instances of:
//! - [`ModuleSender`] to send events
//! - [`ModuleReceiver`] to receive events
//! - [`ErrorSender`] to raise unrecoverable errors
//! - [`tokio::sync::watch::Receiver`] to get the configuration
//!
//! Check specific structs for more informations.
//!
//! # Example
//!
//! In this following lines an implementation of a modules emitting a fake event.
//!
//! ```
//! use pulsar_core::pdk::{
//!     ModuleContext, Payload, PulsarModule, PulsarModuleTask, Version, CleanExit,
//!     ShutdownSignal, ModuleError,
//! };
//! use tokio::time::{sleep, Duration};
//!
//! pub fn my_module() -> PulsarModule {
//!     PulsarModule::new(
//!         "my-module",
//!         Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
//!         my_module_task,
//!     )
//! }
//!
//! async fn my_module_task(
//!     ctx: ModuleContext,
//!     mut shutdown: ShutdownSignal
//! ) -> Result<CleanExit, ModuleError> {
//!     let bus_sender = ctx.get_sender();
//!     loop {
//!         tokio::select! {
//!             r = shutdown.recv() => return r,
//!             _ = sleep(Duration::from_secs(1)) => {
//!                 let pid = bpf_common::Pid::from_raw(1999);
//!                 let timestamp = 1312987.into();
//!                     bus_sender.send(pid, timestamp, Payload::Exit { exit_code: 0 });
//!             }
//!         }
//!     }
//! }
//!  ```
//!
//!
//! [^note]: For the correct type signature check [`PulsarModule::new`]

mod config;
mod daemon;
mod module;
mod module_context;
pub mod process_tracker;

pub use crate::bus::BusError;
pub use crate::event::Event;
pub use crate::event::Payload;
pub use config::*;
pub use daemon::*;
pub use module::*;
pub use module_context::*;
pub use semver::Version;
