//! This module includes all the necessary to build modules for Pulsar
//!
//! Modules implement either [`PulsarModule`] (full control) or [`SimplePulsarModule`] (simpler API).
//! The trait-based API defines:
//! - associated types for configuration and state (and optionally an extension and trigger output)
//! - constants `MODULE_NAME` and `DEFAULT_ENABLED`
//! - async lifecycle methods: `init_state`, `on_event`, `on_config_change`, optional `trigger`/`action`, and `graceful_stop`
//!
//! The [`ModuleContext`] is the entrypoint to the agent features. It lets a module:
//! - send events via `ModuleContext::send` and `send_derived`
//! - emit threats via `send_threat` and `send_threat_derived`
//! - interact with the process tracker and BPF context
//! - raise warnings and errors to the daemon
//!
//! Configuration updates and events are delivered by the runtime to the trait methods.
//!
//! Check specific structs and traits for more informations.
//!
//! # Example
//!
//! In this example, a module prints the process pid if the image equals "/usr/bin/cat" inside `on_event`.
//!
//! ```
//! use pulsar_core::pdk::{Event, ModuleContext, ModuleError, SimplePulsarModule, NoConfig};
//!
//! pub struct PrintCatPid;
//!
//! impl SimplePulsarModule for PrintCatPid {
//!     type Config = NoConfig;
//!     type State = ();
//!
//!     const MODULE_NAME: &'static str = "print-cat-pid";
//!     const DEFAULT_ENABLED: bool = true;
//!
//!     async fn init_state(
//!         &self,
//!         _config: &Self::Config,
//!         _ctx: &ModuleContext,
//!     ) -> Result<Self::State, ModuleError> {
//!         Ok(())
//!     }
//!
//!     async fn on_event(
//!         event: &Event,
//!         _config: &Self::Config,
//!         _state: &mut Self::State,
//!         _ctx: &ModuleContext,
//!     ) -> Result<(), ModuleError> {
//!         if event.header().image == "/usr/bin/cat" {
//!             println!("cat executed with pid {}", event.header().pid);
//!         }
//!         Ok(())
//!     }
//! }
//! ```
//!
//!
//! ## Another example
//!
//! In this following lines an implementation of a modules emitting a fake event.
//!
//! ```
//! use pulsar_core::pdk::{ModuleContext, ModuleError, Payload, PulsarModule, NoConfig};
//! use tokio::time::{self, Duration};
//!
//! pub struct MyModule;
//!
//! impl PulsarModule for MyModule {
//!     type Config = NoConfig;
//!     type State = ();
//!     type Extension = time::Interval;
//!     type TriggerOutput = ();
//!
//!     const MODULE_NAME: &'static str = "my-module";
//!     const DEFAULT_ENABLED: bool = true;
//!
//!     async fn init_state(
//!         &self,
//!         _config: &Self::Config,
//!         _ctx: &ModuleContext,
//!     ) -> Result<(Self::State, Self::Extension), ModuleError> {
//!         let interval = time::interval(Duration::from_secs(1));
//!         Ok(((), interval))
//!     }
//!
//!     async fn trigger(
//!         extension: &mut Self::Extension,
//!     ) -> Result<Self::TriggerOutput, ModuleError> {
//!         extension.tick().await;
//!         Ok(())
//!     }
//!
//!     async fn action(
//!         _trigger_output: &Self::TriggerOutput,
//!         _config: &Self::Config,
//!         _state: &mut Self::State,
//!         ctx: &ModuleContext,
//!     ) -> Result<(), ModuleError> {
//!         let pid = bpf_common::Pid::from_raw(1999);
//!         let timestamp = 1_312_987.into();
//!         ctx.send(pid, timestamp, Payload::Exit { exit_code: 0 });
//!         Ok(())
//!     }
//! }
//! ```
//!
//! [^note]: For the complete API see the [`PulsarModule`] trait.

mod config;
mod daemon;
mod module;
mod module_context;
pub mod process_tracker;

use std::sync::Arc;

pub use crate::bus::BusError;
pub use crate::event::Event;
pub use crate::event::Payload;
pub use config::*;
pub use daemon::*;
pub use module::*;
pub use module_context::*;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

/// Receive an event from a [[broadcast::Receiver]]. Log a warning if we have lost messages
pub async fn receive_from_broadcast(
    rx: &mut broadcast::Receiver<Arc<Event>>,
    module_name: &str,
) -> Result<Arc<Event>, ModuleError> {
    let mut lost: u64 = 0;
    loop {
        match rx.recv().await {
            Ok(value) => {
                if lost > 0 {
                    log::warn!(
                        target: module_name,
                        "brodcast channel lagged {lost} messages",
                    );
                }
                return Ok(value);
            }
            Err(RecvError::Lagged(lagged)) => lost += lagged,
            Err(RecvError::Closed) => return Err("broadcast channel closed".into()),
        }
    }
}
