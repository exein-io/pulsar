use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
    ShutdownSignal, Version,
};
use tokio::sync::watch;

const MODULE_NAME: &str = "logger";

pub fn module() -> PulsarModule {
    PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), logger_task)
}

async fn logger_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_cfg::<Config>();
    let mut logger = Logger::from_config(&rx_config)?;

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                logger = Logger::from_config(&rx_config)?;
            }
            msg = receiver.recv() => {
                let msg = msg?;
                if msg.header.is_threat {
                    logger.process(&msg)
                }
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
    fn from_config(
        rx_config: &watch::Receiver<Result<Config, ConfigError>>,
    ) -> Result<Self, ModuleError> {
        let Config { console } = rx_config.borrow().clone()?;
        Ok(Self { console })
    }

    fn process(&self, event: &Event) {
        if self.console {
            println!("{:?}", event);
        }
    }
}
