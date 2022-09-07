mod rotation;
mod error;

use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
    ShutdownSignal, Version,
};
use rotation::{FileRotation, RotationMode};
use tokio::sync::watch;
use tokio::io::AsyncWriteExt;

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
    let mut logger = Logger::from_config(&rx_config).await?;

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                logger = Logger::from_config(&rx_config).await?;
            }
            msg = receiver.recv() => {
                let msg = msg?;
                if msg.header.is_threat {
                    logger.process(&msg).await?;
                }
            },
        }
    }
}

#[derive(Clone)]
struct Config {
    console: bool,

    /// Log file configuration
    file: bool,
    file_dir: String,   // root directory for log files, default is /var/log/pulsar/
    rotation_size: usize, // Max size (in kilobytes) of the file after which it will rotate, default: 10MB

    // syslog: bool, //TODO:
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    #[allow(clippy::identity_op)]
    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            console: config.required("console").unwrap_or(true),

            file: config.with_default("file", false)?,
            file_dir: config.with_default("file_dir", "/var/log/pulsar/".to_string())?,
            rotation_size: config.with_default("rotation_size", 10 * 1024)?,
            // syslog: config.required("syslog")?,
        })
    }
}

struct Logger {
    console: bool,
    file: bool,
    file_rotation: Option<FileRotation>,
}

impl Logger {
    async fn from_config(
        rx_config: &watch::Receiver<Result<Config, ConfigError>>,
    ) -> Result<Self, ModuleError> {
        let Config { 
            console, 
            file, 
            file_dir, 
            rotation_size, 
        } = rx_config.borrow().clone()?;
        //handle file logging
        let mut file_rotation = None;
        if file {
            // tokio::spawn(async move {
                file_rotation = Some(FileRotation::new(
                    &file_dir,
                    RotationMode::SizeExceeded(rotation_size),
                    5 //TODO: make this configurable
                ).await?);
            // });
        }
        Ok(Self { 
            console, 
            file, 
            file_rotation
        })
    }

    async fn process(&mut self, event: &Event) -> std::io::Result<()> {
        if self.console {
            println!("{:?}", event);
        }
        if self.file {
            let event_bytes = serde_json::to_vec(event)?;
            //TODO: im getting the error here - cannot move out of `self.file_rotation` which is behind a mutable reference
            // if possible, can you advise how to fix it?
            // self.file_rotation.expect("file_rotation is not empty").write(&event_bytes).await?;
        }
        Ok(())
    }
}
