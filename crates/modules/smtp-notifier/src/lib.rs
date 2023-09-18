use std::{default::Default, error::Error, fmt, str::FromStr};

use lettre::message::Mailbox;
use pulsar_core::event::Threat;
use pulsar_core::pdk::{
    CleanExit, ConfigError, ModuleConfig, ModuleContext, ModuleError, PulsarModule, ShutdownSignal,
    Version,
};

use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};

const MODULE_NAME: &str = "smtp-notifier";

pub fn module() -> PulsarModule {
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        smtp_notifier_task,
    )
}

async fn smtp_notifier_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_config();
    let mut config: SmtpNotifierConfig = rx_config.read()?;

    loop {
        tokio::select! {
            // Handle configuration changes:
            _ = rx_config.changed() => {
                config = rx_config.read()?;
                continue;
            }
            r = shutdown.recv() => return r,
            msg = receiver.recv() => {
                let event = msg?;

                // Check if the even is a threat and send a email if it is
                if let Some(Threat {
                    source,
                    description,
                    extra: _,
                }) = &event.header().threat
                {
                    let payload = event.payload();
                    let subject = format!("Pulsar Threat Notification: {source}");
                    let body = format!("{description}\n Source event: {payload}");

                    let mut message_builder = Message::builder()
                        .to(config.receiver.clone())
                        .subject(subject);

                    if let Some(sender) =  &config.sender {
                        message_builder = message_builder.from(sender.clone());
                    }

                    let message = message_builder.body(body)?;

                    let smtp_transport = match config.encryption {
                        Encryption::None => {
                            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(config.server.as_str())
                        }
                        Encryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(config.server.as_str())?,
                        Encryption::StartTls => {
                            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(config.server.as_str())?
                        }
                    };

                    smtp_transport
                        .credentials(Credentials::new(config.user.clone(), config.password.clone()))
                        .port(config.port)
                        .build()
                        .send(message)
                        .await?;
                }
            }
        }
    }
}

#[derive(Debug)]
struct ParseEncryptionError;

impl Error for ParseEncryptionError {}

impl fmt::Display for ParseEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Default, Clone, Copy)]
enum Encryption {
    #[default]
    Tls,
    StartTls,
    None,
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Encryption {
    type Err = ParseEncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Encryption::None),
            "tls" => Ok(Encryption::Tls),
            "starttls" => Ok(Encryption::StartTls),
            _ => Err(ParseEncryptionError),
        }
    }
}

#[derive(Clone, Debug)]
struct SmtpNotifierConfig {
    server: String,
    user: String,
    password: String,
    receiver: Mailbox,
    port: u16,
    encryption: Encryption,
    sender: Option<Mailbox>,
}

impl TryFrom<&ModuleConfig> for SmtpNotifierConfig {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let sender = match config.get_raw("sender") {
            Some(s) => {
                let mailbox = s
                    .parse::<Mailbox>()
                    .map_err(|err| ConfigError::InvalidValue {
                        field: "sender".to_string(),
                        value: s.to_string(),
                        err: err.to_string(),
                    })?;

                Some(mailbox)
            }
            None => None,
        };

        Ok(SmtpNotifierConfig {
            server: config.required::<String>("server")?,
            user: config.required::<String>("user")?,
            password: config.required::<String>("password")?,
            receiver: config.required::<Mailbox>("receiver")?,
            port: config.with_default::<u16>("port", 465)?,
            encryption: config.with_default::<Encryption>("encryption", Default::default())?,
            sender,
        })
    }
}
