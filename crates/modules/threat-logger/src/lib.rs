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

use pulsar_core::pdk::{
    ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, SimplePulsarModule,
};
use thiserror::Error;

const UNIX_SOCK_PATHS: [&str; 3] = ["/dev/log", "/var/run/syslog", "/var/run/log"];
const PRIORITY: u8 = 25; // facility * 8 + severity. facility: daemon (3); severity: alert (1)

pub struct ThreatLoggerModule;

impl SimplePulsarModule for ThreatLoggerModule {
    type Config = Config;
    type State = ThreatLoggerState;

    const MODULE_NAME: &'static str = "threat-logger";
    const DEFAULT_ENABLED: bool = true;
    const DEPENDS_ON: &'static [&'static str] = &[];

    async fn init_state(
        &self,
        config: &Self::Config,
        ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        let logger = match ThreatLogger::from_config(config) {
            Ok(logr) => logr,
            Err(logr) => {
                ctx.raise_warning("Failed to connect to syslog".into())
                    .await;
                logr
            }
        };

        Ok(ThreatLoggerState { logger })
    }

    async fn on_config_change(
        new_config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        state.logger = match ThreatLogger::from_config(new_config) {
            Ok(logr) => logr,
            Err(logr) => {
                ctx.raise_warning("Failed to connect to syslog".into())
                    .await;
                logr
            }
        };
        Ok(())
    }

    async fn on_event(
        event: &Event,
        _config: &Self::Config,
        state: &mut Self::State,
        ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        if let Err(e) = state.logger.process(event) {
            ctx.raise_warning(format!("Writing to logs failed: {e}, syslog disabled"))
                .await;
            state.logger.syslog = None;
        }
        Ok(())
    }
}

pub struct ThreatLoggerState {
    logger: ThreatLogger,
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
pub struct Config {
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
struct ThreatLogger {
    console: bool,
    syslog: Option<UnixDatagram>,
    output_format: OutputFormat,
}

#[derive(Debug, Error)]
enum ThreatLoggerError {
    #[error("error serializing event: {0}")]
    Json(String),
    #[error("io error")]
    IO(#[from] io::Error),
}

impl ThreatLogger {
    fn from_config(config: &Config) -> Result<Self, Self> {
        let Config {
            console,
            syslog,
            output_format,
        } = config;

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

        let opt_sock = (*syslog && !connected_to_journal)
            .then(|| {
                let sock = UnixDatagram::unbound().ok()?;
                UNIX_SOCK_PATHS
                    .iter()
                    .find_map(|path| sock.connect(path).ok())
                    .map(|_| sock)
            })
            .flatten();

        if *syslog && opt_sock.is_none() {
            Err(Self {
                console: *console,
                syslog: opt_sock,
                output_format: output_format.clone(),
            })
        } else {
            Ok(Self {
                console: *console,
                syslog: opt_sock,
                output_format: output_format.clone(),
            })
        }
    }

    fn process(&mut self, event: &Event) -> Result<(), ThreatLoggerError> {
        if event.header().threat.is_some() {
            let json_event = OnceCell::new();
            let json_event = || -> Result<&String, ThreatLoggerError> {
                json_event
                    .get_or_init(|| serde_json::to_string(event))
                    .as_ref()
                    .map_err(|err| ThreatLoggerError::Json(err.to_string()))
            };

            if self.console {
                let out = match self.output_format {
                    OutputFormat::Plaintext => Cow::Owned(format!("{event:#}")),
                    OutputFormat::Json => Cow::Borrowed(json_event()?),
                };
                println!("{out}");
            }

            if let Some(syslog) = &mut self.syslog {
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
