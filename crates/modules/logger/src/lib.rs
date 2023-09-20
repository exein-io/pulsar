use async_trait::async_trait;
use pulsar_core::pdk::{
    ConfigError, Event, Module, ModuleConfig, ModuleContext, ModuleError, PulsarModule, Version,
};

const MODULE_NAME: &str = "logger";

pub struct Logger {
    console: bool,
    // file: bool, //TODO:
    // syslog: bool, //TODO:
}

impl TryFrom<&ModuleConfig> for Logger {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            console: config.with_default("console", true)?,
            // file: config.required("file")?,
            // syslog: config.required("syslog")?,
        })
    }
}

impl Logger {
    fn process(&self, event: &Event) {
        if event.header().threat.is_some() && self.console {
            terminal::print_event(event);
        }
    }
}

#[async_trait]
impl Module for Logger {
    fn start() -> PulsarModule {
        PulsarModule::new(
            MODULE_NAME,
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            |ctx: &ModuleContext| {
                let logger: Logger = ctx.get_config().read()?;
                Ok(logger)
            },
        )
    }

    async fn on_event(&mut self, event: &Event, _ctx: &ModuleContext) -> Result<(), ModuleError> {
        self.process(event);
        Ok(())
    }

    fn on_change(&mut self, ctx: &ModuleContext) -> Result<(), ModuleError> {
        let logger: Logger = ctx.get_config().read()?;
        *self = logger;
        Ok(())
    }
}

pub mod terminal {
    use chrono::{DateTime, Utc};
    use pulsar_core::{event::Threat, pdk::Event};

    pub fn print_event(event: &Event) {
        let header = event.header();
        let time = DateTime::<Utc>::from(header.timestamp).format("%Y-%m-%dT%TZ");
        let image = &header.image;
        let pid = &header.pid;
        let payload = event.payload();

        if let Some(Threat {
            source,
            description,
            extra: _,
        }) = &event.header().threat
        {
            println!(
                "[{time} \x1b[1;30;43mTHREAT\x1b[0m  {image} ({pid})] [{source} - {description}] {payload}"
            )
        } else {
            let source = &header.source;
            println!("[{time} \x1b[1;30;46mEVENT\x1b[0m  {image} ({pid})] [{source}] {payload}")
        }
    }
}
