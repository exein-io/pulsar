//! A showcase of what a Pulsar modules can do
use std::collections::HashMap;

use pulsar_core::pdk::{
    ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, Payload, SimplePulsarModule,
};

pub struct MyCustomModule;

impl SimplePulsarModule for MyCustomModule {
    type Config = MyModuleConfig;
    type State = MyState;

    const MODULE_NAME: &'static str = "my-custom-module";
    const DEFAULT_ENABLED: bool = true;

    async fn init_state(
        &self,
        _config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        Ok(Self::State { dns_query_count: 0 })
    }

    // Handle configuration changes:
    async fn on_config_change(
        new_config: &Self::Config,
        _state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        println!("Configuration changed: {new_config:?}");
        Ok(())
    }

    async fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        // ModuleContext allows our module to access the agent features
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        if config.print_events {
            println!("{event:?}");
        }

        // Identify events as threats:
        if let Some(forbidden_dns) = &config.forbidden_dns {
            if let Payload::DnsQuery { questions } = event.payload() {
                // Update the state
                state.dns_query_count += 1;

                if questions
                    .iter()
                    .any(|question| &question.name == forbidden_dns)
                {
                    let desc = "Forbidden DNS query".to_string();
                    let mut extra = HashMap::new();
                    extra.insert("anomaly_score".to_string(), "1.0".to_string());

                    ctx.send_threat_derived(&event, desc, Some(extra.into()));
                }
            }
        }

        Ok(())
    }
}

/// An example state. You can put a state for the module here,
pub struct MyState {
    dns_query_count: u64,
}

/// An exmaple configuration. You can put whatever you want here,
/// as long as you implement `TryFrom<&ModuleConfig>`
#[derive(Clone, Debug, Default)]
pub struct MyModuleConfig {
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
