use std::{default::Default, error::Error, fmt, str::FromStr};

use anyhow::Context;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use pulsar_core::{
    event::Threat,
    pdk::{ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, SimplePulsarModule},
};

mod template;

pub struct SmtpNotifierModule;

impl SimplePulsarModule for SmtpNotifierModule {
    type Config = SmtpNotifierConfig;
    type State = SmtpNotifierState;

    const MODULE_NAME: &'static str = "smtp-notifier";
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        _config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        Ok(Self::State {
            template: template::Template::new()?,
        })
    }

    async fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        handle_event(config, event, &state.template).await
    }
}

pub struct SmtpNotifierState {
    template: template::Template,
}

async fn handle_event(
    config: &SmtpNotifierConfig,
    event: &Event,
    template: &template::Template,
) -> Result<(), ModuleError> {
    let header = event.header();

    // Check if the even is a threat and send a email if it is
    if let Some(Threat {
        source,
        description,
        extra: _,
    }) = &header.threat
    {
        let payload = event.payload();
        let subject = format!("Pulsar Threat Notification - {}", rand::random::<u64>());
        let body = template
            .render(
                &header.timestamp,
                source,
                &header.image,
                description,
                payload,
            )
            .context("error filling the email template")?;

        let mut message_builder = Message::builder()
            .subject(subject)
            .from(config.sender.clone())
            .header(ContentType::TEXT_HTML);

        for receiver in config.receivers.iter() {
            message_builder = message_builder.to(receiver.clone())
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
            .credentials(Credentials::new(
                config.username.clone(),
                config.password.clone(),
            ))
            .port(config.port)
            .build()
            .send(message)
            .await?;
    }

    Ok(())
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
pub struct SmtpNotifierConfig {
    server: String,
    username: String,
    password: String,
    receivers: Vec<Mailbox>,
    port: u16,
    encryption: Encryption,
    sender: Mailbox,
}

impl TryFrom<&ModuleConfig> for SmtpNotifierConfig {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let username = config.required::<String>("username")?;

        // Get sender from `sender` field or try to parse `username` as an email
        let sender = match config.get_raw("sender") {
            Some(s) => s
                .parse::<Mailbox>()
                .map_err(|err| ConfigError::InvalidValue {
                    field: "sender".to_string(),
                    value: s.to_string(),
                    err: err.to_string(),
                })?,
            None => username
                .parse::<Mailbox>()
                .map_err(|err| ConfigError::InvalidValue {
                    field: "username".to_string(),
                    value: username.to_string(),
                    err: format!(
                        "if `username` is not the email address, a `sender` must be set: {err}"
                    ),
                })?,
        };

        let receivers = config.get_list::<Mailbox>("receivers")?;

        if receivers.is_empty() {
            return Err(ConfigError::RequiredValue {
                field: "receivers".to_string(),
            });
        }

        Ok(SmtpNotifierConfig {
            server: config.required::<String>("server")?,
            username,
            password: config.required::<String>("password")?,
            receivers,
            port: config.with_default::<u16>("port", 465)?,
            encryption: config.with_default::<Encryption>("encryption", Default::default())?,
            sender,
        })
    }
}
