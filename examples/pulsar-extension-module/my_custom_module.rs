//! A showcase of what a Pulsar modules can do
use std::{collections::HashMap, sync::Arc};

use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, Payload, PulsarModule,
    ShutdownSignal, Version,
};

const MODULE_NAME: &str = "my-custom-module";

pub fn module() -> PulsarModule {
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        module_task,
    )
}

async fn module_task(
    // ModuleContext allows our module to access the agent features
    ctx: ModuleContext,
    // ShutdownSignal will be used by the agent to stop this module
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    // Get a receiver for all module events.
    let mut receiver = ctx.get_receiver();

    // Get the configuration of your own module
    let mut rx_config = ctx.get_config();
    let mut config: MyModuleConfig = rx_config.read()?;

    // Get a channel for sending new events
    let sender = ctx.get_sender();

    loop {
        tokio::select! {
            // Handle configuration changes:
            _ = rx_config.changed() => {
                config = rx_config.read()?;
                println!("Configuration changed: {config:?}");
            }

            // Receive events from other modules:
            event = receiver.recv() => {
                let event: Arc<Event> = event?;
                if config.print_events {
                    println!("{event:?}");
                }
                // Identify events as threats:
                if let Some(forbidden_dns) = &config.forbidden_dns {
                    if let Payload::DnsQuery { questions } = event.payload() {
                        if questions.iter().any(|question| &question.name == forbidden_dns) {
                            let mut info = HashMap::new();
                            info.insert("anomaly_score".to_string(), "1.0".to_string());

                            sender.send_threat_derived(
                                &event,
                                info
                            );
                        }
                    }
                }
            },

            // Stop when receiving the shudown signal:
            r = shutdown.recv() => return r,
        }
    }
}

/// An exmaple configuration. You can put whatever you want here,
/// as long as you implement `TryFrom<&ModuleConfig>`
#[derive(Clone, Debug, Default)]
struct MyModuleConfig {
    /// Enable printing events to stdout
    print_events: bool,
    /// Generate a threat event when resolving this domain name
    forbidden_dns: Option<String>,
}

impl TryFrom<&ModuleConfig> for MyModuleConfig {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(MyModuleConfig {
            print_events: config.with_default("print_events", false)?,
            forbidden_dns: config.get_raw("forbidden_dns").map(String::from),
        })
    }
}
