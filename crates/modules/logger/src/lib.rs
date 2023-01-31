use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
    ShutdownSignal, Version,
};

const MODULE_NAME: &str = "logger";

pub fn module() -> PulsarModule {
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        logger_task,
    )
}

async fn logger_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_config();
    let mut logger = Logger::from_config(rx_config.read()?);

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                logger = Logger::from_config(rx_config.read()?);
            }
            msg = receiver.recv() => {
                let msg = msg?;
                logger.process(&msg)
            },
        }
    }
}

#[derive(Clone)]
struct Config {
    console: bool,
    // file: bool, //TODO:
    // syslog: bool, //TODO:
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            console: config.required("console").unwrap_or(true),
            // file: config.required("file")?,
            // syslog: config.required("syslog")?,
        })
    }
}

struct Logger {
    console: bool,
}

impl Logger {
    fn from_config(rx_config: Config) -> Self {
        let Config { console } = rx_config;
        Self { console }
    }

    fn process(&self, event: &Event) {
        if event.header().threat.is_some() && self.console {
            terminal::print_event(event);
        }
    }
}

pub mod terminal {
    use chrono::{DateTime, Utc};
    use pulsar_core::{event::Threat, pdk::Event};

    pub fn print_event(event: &Event) {
        let header = event.header();
        let time = DateTime::<Utc>::from(header.timestamp);
        let image = &header.image;
        let pid = &header.pid;
        let payload = event.payload();

        if let Some(Threat { source, info }) = &event.header().threat {
            println!(
                "[{time} \x1b[1;30;43mTHREAT\x1b[0m {image} ({pid})] [{source} - {info}] {payload}"
            )
        } else {
            let source = &header.source;
            println!("[{time} \x1b[1;30;46mEVENT\x1b[0m {image} ({pid})] [{source}] {payload}")
        }
    }
}
