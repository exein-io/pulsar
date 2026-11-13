//! Prints threats to the console and sends them to syslog.

use std::{
    borrow::Cow,
    cell::OnceCell,
    env,
    fmt::Write,
    fs::File,
    io,
    os::{
        fd::AsFd,
        unix::{fs::MetadataExt, net::UnixDatagram},
    },
    sync::Arc,
    time::SystemTime,
};

use next_core::{
    Schema,
    processor::{ReportError, Reporter},
    threat::{Ancestor, ProcessSnapshot, Threat, ThreatKindSet},
};
use serde::Deserialize;
use thiserror::Error;

const UNIX_SOCK_PATHS: [&str; 3] = ["/dev/log", "/var/run/syslog", "/var/run/log"];
const PRIORITY: u8 = 25; // facility * 8 + severity. facility: daemon (3); severity: alert (1)

impl<S: Schema> Reporter<S> for ThreatLogger {
    fn name(&self) -> &'static str {
        "threat-logger"
    }

    async fn report(&mut self, threat: Arc<Threat<S>>) -> Result<(), ReportError> {
        if let Err(e) = self.process(&threat) {
            self.syslog = None;
            return Err(format!("writing to logs failed: {e}, syslog disabled").into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum OutputFormat {
    #[default]
    Plaintext,
    Json,
}

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Log threats to stdout.
    console: bool,
    /// Log threats to syslog.
    syslog: bool,
    /// Rendering of the logged threats.
    output_format: OutputFormat,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            console: true,
            syslog: true,
            output_format: OutputFormat::default(),
        }
    }
}

#[derive(Debug)]
pub struct ThreatLogger {
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
    /// Returns the logger, and whether syslog was wanted but unreachable.
    pub fn new(config: &Config) -> (Self, bool) {
        match Self::from_config(config) {
            Ok(logger) => (logger, false),
            Err(logger) => (logger, true),
        }
    }

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

    fn process<S: Schema>(&mut self, threat: &Threat<S>) -> Result<(), ThreatLoggerError> {
        let json_threat = OnceCell::new();
        let json_threat = || -> Result<&String, ThreatLoggerError> {
            json_threat
                .get_or_init(|| serde_json::to_string(threat))
                .as_ref()
                .map_err(|err| ThreatLoggerError::Json(err.to_string()))
        };

        if self.console {
            let out = match self.output_format {
                OutputFormat::Plaintext => Cow::Owned(plaintext(threat, true)),
                OutputFormat::Json => Cow::Borrowed(json_threat()?),
            };
            println!("{out}");
        }

        if let Some(syslog) = &mut self.syslog {
            let out = match self.output_format {
                OutputFormat::Plaintext => format!("<{PRIORITY}>{}", plaintext(threat, false)),
                OutputFormat::Json => format!("<{PRIORITY}>{}", json_threat()?),
            };
            syslog.send(out.as_bytes())?;
        }
        Ok(())
    }
}

/// One line for the threat, one per ancestor.
fn plaintext<S: Schema>(threat: &Threat<S>, color: bool) -> String {
    let time = threat
        .timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let label = if color {
        "\x1b[1;30;43mTHREAT\x1b[0m"
    } else {
        "THREAT"
    };
    let mut out = format!(
        "[{time} {label} {}] [{}/{} - {}]",
        process(&threat.subject),
        threat.detector,
        threat.kind.name(),
        threat.description,
    );
    if let Some(event) = &threat.event {
        let _ = write!(out, " {:?}", event.payload);
    }
    // The lineage is under review, see next_core::table.
    for ancestor in &threat.lineage {
        let _ = match ancestor {
            Ancestor::Known {
                process: ancestor,
                window,
                window_spans_gap,
            } => write!(
                out,
                "\n  <- {} ({} recent events{})",
                process(ancestor),
                window.len(),
                if *window_spans_gap { ", some lost" } else { "" }
            ),
            Ancestor::Unknown { pid: Some(pid) } => write!(out, "\n  <- ? ({pid})"),
            Ancestor::Unknown { pid: None } => write!(out, "\n  <- ?"),
        };
    }
    out
}

fn process(process: &ProcessSnapshot) -> String {
    let image = process
        .image
        .as_ref()
        .map_or_else(|| "?".to_string(), ToString::to_string);
    match process.pid {
        Some(pid) => format!("{image} ({pid})"),
        None => image.to_string(),
    }
}
