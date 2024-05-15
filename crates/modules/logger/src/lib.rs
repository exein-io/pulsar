use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
    ShutdownSignal,
};
use std::{
    borrow::Cow,
    cell::OnceCell,
    env,
    fs::File,
    io,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, net::UnixDatagram},
    },
    str::FromStr,
};
use thiserror::Error;

const UNIX_SOCK_PATHS: [&str; 3] = ["/dev/log", "/var/run/syslog", "/var/run/log"];
const PRIORITY: u8 = 25; // facility * 8 + severity. facility: daemon (3); severity: alert (1)

pub struct LoggerModule;

impl PulsarModule for LoggerModule {
    const MODULE_NAME: &'static str = "threat-logger";
    const DEFAULT_ENABLED: bool = true;

    fn start(
        &self,
        ctx: ModuleContext,
        shutdown: ShutdownSignal,
    ) -> impl std::future::Future<Output = Result<CleanExit, ModuleError>> + Send + 'static {
        logger_task(ctx, shutdown)
    }
}

async fn logger_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_config();
    let sender = ctx.get_sender();

    let mut logger = match Logger::from_config(rx_config.read()?) {
        Ok(logr) => logr,
        Err(logr) => {
            sender
                .raise_warning("Failed to connect to syslog".into())
                .await;
            logr
        }
    };

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                logger = match Logger::from_config(rx_config.read()?) {
                    Ok(logr) => logr,
                    Err(logr) => {
                        sender.raise_warning("Failed to connect to syslog".into()).await;
                        logr
                    }
                }
            }
            msg = receiver.recv() => {
                let msg = msg?;
                if let Err(e) = logger.process(&msg) {
                    sender.raise_warning(format!("Writing to logs failed: {e}")).await;
                    logger = Logger { syslog: None, ..logger };
                }
            },
        }
    }
}

#[derive(Clone, Debug)]
enum OutputFormat {
    Plaintext,
    Json,
}

impl FromStr for OutputFormat {
    type Err = ConfigError;
    fn from_str(format: &str) -> Result<Self, Self::Err> {
        match format.to_lowercase().as_str() {
            "plaintext" => Ok(OutputFormat::Plaintext),
            "json" => Ok(OutputFormat::Json),
            _ => Err(ConfigError::InvalidValue {
                field: String::from("output_format"),
                value: format.to_string(),
                err: String::from("Output format must be one of [plaintext, json]"),
            }),
        }
    }
}

#[derive(Clone)]
struct Config {
    console: bool,
    // file: bool, //TODO:
    syslog: bool,
    output_format: OutputFormat,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            console: config.with_default("console", true)?,
            // file: config.required("file")?,
            syslog: config.with_default("syslog", true)?,
            output_format: config.with_default("output_format", OutputFormat::Plaintext)?,
        })
    }
}

#[derive(Debug)]
struct Logger {
    console: bool,
    syslog: Option<UnixDatagram>,
    output_format: OutputFormat,
}

#[derive(Debug, Error)]
enum LoggerError {
    #[error("error serializing event: {0}")]
    Json(String),
    #[error("io error")]
    IO(#[from] io::Error),
}

impl Logger {
    fn from_config(rx_config: Config) -> Result<Self, Self> {
        let Config {
            console,
            syslog,
            output_format,
        } = rx_config;

        let connected_to_journal = io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .and_then(|fd| File::from(fd).metadata())
            .map(|meta| format!("{}:{}", meta.dev(), meta.ino()))
            .ok()
            .and_then(|stderr| {
                env::var_os("JOURNAL_STREAM").map(|s| s.to_string_lossy() == stderr.as_str())
            })
            .unwrap_or(false);

        let opt_sock = (syslog && !connected_to_journal)
            .then(|| {
                let sock = UnixDatagram::unbound().ok()?;
                UNIX_SOCK_PATHS
                    .iter()
                    .find_map(|path| sock.connect(path).ok())
                    .map(|_| sock)
            })
            .flatten();

        if syslog && opt_sock.is_none() {
            Err(Self {
                console,
                syslog: opt_sock,
                output_format,
            })
        } else {
            Ok(Self {
                console,
                syslog: opt_sock,
                output_format,
            })
        }
    }

    fn process(&mut self, event: &Event) -> Result<(), LoggerError> {
        if event.header().threat.is_some() {
            let json_event = OnceCell::new();
            let json_event = || -> Result<&String, LoggerError> {
                json_event
                    .get_or_init(|| serde_json::to_string(event))
                    .as_ref()
                    .map_err(|err| LoggerError::Json(err.to_string()))
            };

            if self.console {
                let out = match self.output_format {
                    OutputFormat::Plaintext => Cow::Owned(format!("{event:#}")),
                    OutputFormat::Json => Cow::Borrowed(json_event()?),
                };
                println!("{out}");
            }

            if let Some(ref mut syslog) = &mut self.syslog {
                let out = match self.output_format {
                    OutputFormat::Plaintext => format!("<{PRIORITY}>{event}"),
                    OutputFormat::Json => format!("<{PRIORITY}>{}", json_event()?),
                };
                syslog.send(out.as_bytes())?;
            }
        }
        Ok(())
    }
}
