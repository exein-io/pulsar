use std::{default::Default, error::Error, fmt, str::FromStr};

use lettre::message::Mailbox;
use pulsar_core::event::Threat;
use pulsar_core::pdk::{
    ConfigError, Event, Module, ModuleConfig, ModuleContext, ModuleError, PulsarModule, Version,
};

use async_trait::async_trait;
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};

const MODULE_NAME: &str = "smtp-notifier";

#[derive(Clone, Debug)]
pub struct SmtpNotifier {
    server: String,
    user: String,
    password: String,
    receivers: Vec<Mailbox>,
    port: u16,
    encryption: Encryption,
    sender: Option<Mailbox>,
}

impl TryFrom<&ModuleConfig> for SmtpNotifier {
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

        let receivers = config.get_list::<Mailbox>("receivers")?;

        if receivers.is_empty() {
            return Err(ConfigError::RequiredValue {
                field: "receivers".to_string(),
            });
        }

        Ok(Self {
            server: config.required::<String>("server")?,
            user: config.required::<String>("user")?,
            password: config.required::<String>("password")?,
            receivers,
            port: config.with_default::<u16>("port", 465)?,
            encryption: config.with_default::<Encryption>("encryption", Default::default())?,
            sender,
        })
    }
}

#[async_trait]
impl Module for SmtpNotifier {
    fn start() -> PulsarModule {
        PulsarModule::new(
            MODULE_NAME,
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
            |ctx: &ModuleContext| {
                let smtp_notifier: SmtpNotifier = ctx.get_config().read()?;
                Ok(smtp_notifier)
            },
        )
    }

    fn on_change(&mut self, ctx: &ModuleContext) -> Result<(), ModuleError> {
        let smtp_notifier: SmtpNotifier = ctx.get_config().read()?;
        *self = smtp_notifier;
        Ok(())
    }

    async fn on_event(&mut self, event: &Event, _ctx: &ModuleContext) -> Result<(), ModuleError> {
        if let Some(Threat {
            source,
            description,
            extra: _,
        }) = &event.header().threat
        {
            let payload = event.payload();
            let subject = format!("Pulsar Threat Notification: {source}");
            let body = format!("{description}\n Source event: {payload}");

            let mut message_builder = Message::builder().subject(subject);

            for receiver in self.receivers.iter() {
                message_builder = message_builder.to(receiver.clone())
            }

            if let Some(sender) = &self.sender {
                message_builder = message_builder.from(sender.clone());
            }

            let message = message_builder.body(body)?;

            let smtp_transport = match self.encryption {
                Encryption::None => {
                    AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(self.server.as_str())
                }
                Encryption::Tls => {
                    AsyncSmtpTransport::<Tokio1Executor>::relay(self.server.as_str())?
                }
                Encryption::StartTls => {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(self.server.as_str())?
                }
            };

            smtp_transport
                .credentials(Credentials::new(self.user.clone(), self.password.clone()))
                .port(self.port)
                .build()
                .send(message)
                .await?;
        }

        Ok(())
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
