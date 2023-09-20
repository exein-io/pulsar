//! A showcase of what a Pulsar modules can do
use std::collections::HashMap;

use pulsar_core::pdk::{
    ConfigError, Event, Module, ModuleConfig, ModuleContext, ModuleError, Payload, PulsarModule,
    Version,
};

use async_trait::async_trait;

const MODULE_NAME: &str = "my-custom-module";

#[derive(Clone, Debug, Default)]
pub struct MyCustomModule {
    /// Enable printing events to stdout
    print_events: bool,
    /// Generate a threat event when resolving this domain name
    forbidden_dns: Option<String>,
}

impl TryFrom<&ModuleConfig> for MyCustomModule {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            print_events: config.with_default("print_events", false)?,
            forbidden_dns: config.get_raw("forbidden_dns").map(String::from),
        })
    }
}

#[async_trait]
impl Module for MyCustomModule {
    fn start() -> PulsarModule {
        PulsarModule::new(
            MODULE_NAME,
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            |ctx: &ModuleContext| {
                let my_custom_module: MyCustomModule = ctx.get_config().read()?;
                Ok(my_custom_module)
            },
        )
    }
    fn on_change(&mut self, _ctx: &ModuleContext) -> Result<(), ModuleError> {
        println!("configuration changed");
        Ok(())
    }
    async fn on_event(&mut self, event: &Event, ctx: &ModuleContext) -> Result<(), ModuleError> {
        let sender = ctx.get_sender();

        if self.print_events {
            println!("{event:?}");
        }
        // Identify events as threats:
        if let Some(forbidden_dns) = &self.forbidden_dns {
            if let Payload::DnsQuery { questions } = event.payload() {
                if questions
                    .iter()
                    .any(|question| &question.name == forbidden_dns)
                {
                    let desc = "Forbidden DNS query".to_string();
                    let mut extra = HashMap::new();
                    extra.insert("anomaly_score".to_string(), "1.0".to_string());

                    sender.send_threat_derived(event, desc, Some(extra.into()));
                }
            }
        }
        Ok(())
    }
}
