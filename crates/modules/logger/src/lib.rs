use pulsar_core::pdk::{
    CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
    ShutdownSignal, Version,
};
use std::{
    env,
    fs::File,
    io,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, net::UnixDatagram},
    },
};

const UNIX_SOCK_PATHS: [&str; 3] = ["/dev/log", "/var/run/syslog", "/var/run/log"];
const MODULE_NAME: &str = "logger";

pub fn module() -> PulsarModule {
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        true,
        logger_task,
    )
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
                    sender.raise_warning(format!("Writing to syslog failed: {e}")).await;
                    logger = Logger { syslog: None, ..logger };
                }
            },
        }
    }
}

#[derive(Clone)]
struct Config {
    console: bool,
    // file: bool, //TODO:
    syslog: bool,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            console: config.with_default("console", true)?,
            // file: config.required("file")?,
            syslog: config.with_default("syslog", true)?,
        })
    }
}

#[derive(Debug)]
struct Logger {
    console: bool,
    syslog: Option<UnixDatagram>,
}

impl Logger {
    fn from_config(rx_config: Config) -> Result<Self, Self> {
        let Config { console, syslog } = rx_config;

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
            })
        } else {
            Ok(Self {
                console,
                syslog: opt_sock,
            })
        }
    }

    fn process(&mut self, event: &Event) -> io::Result<()> {
        if event.header().threat.is_some() {
            if self.console {
                println!("{:#}", event);
            }

            if let Some(ref mut syslog) = &mut self.syslog {
                syslog.send(format!("{}", event).as_bytes())?;
            }
        }
        Ok(())
    }
}
