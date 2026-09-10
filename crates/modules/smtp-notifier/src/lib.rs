use anyhow::{Context, Result, bail};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::authentication::Credentials,
};
use pulsar_core::{
    event::Threat,
    pdk::{Event, ModuleContext, ModuleError, SimplePulsarModule},
};
use serde::{Deserialize, Deserializer, de};

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

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Encryption {
    #[default]
    Tls,
    StartTls,
    None,
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

// TODO: drop the intermediate struct once serde can express both the `sender`
// fallback to `username` and a non-empty `receivers`.
#[derive(Deserialize)]
struct RawConfig {
    /// Address of the SMTP server.
    server: String,
    /// User credential for the SMTP server.
    username: String,
    /// Password credential for the SMTP server.
    password: String,
    /// Addresses notifications are sent to. Must not be empty.
    receivers: Vec<Mailbox>,
    /// Port of the SMTP server.
    #[serde(default = "default_port")]
    port: u16,
    /// Encryption used to reach the SMTP server.
    #[serde(default)]
    encryption: Encryption,
    /// Address notifications are sent from. Defaults to `username`.
    sender: Option<Mailbox>,
}

fn default_port() -> u16 {
    465
}

impl TryFrom<RawConfig> for SmtpNotifierConfig {
    type Error = anyhow::Error;

    fn try_from(raw: RawConfig) -> Result<Self> {
        if raw.receivers.is_empty() {
            bail!("`receivers` must not be empty");
        }

        let sender = match raw.sender {
            Some(sender) => sender,
            None => raw.username.parse::<Mailbox>().with_context(|| {
                "if `username` is not an email address, `sender` must be set".to_string()
            })?,
        };

        Ok(SmtpNotifierConfig {
            server: raw.server,
            username: raw.username,
            password: raw.password,
            receivers: raw.receivers,
            port: raw.port,
            encryption: raw.encryption,
            sender,
        })
    }
}

impl<'de> Deserialize<'de> for SmtpNotifierConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = RawConfig::deserialize(deserializer)?;
        SmtpNotifierConfig::try_from(raw).map_err(|err| de::Error::custom(format!("{err:#}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: &str = r#"
        server = "smtp.example.com"
        password = "secret"
        receivers = ["admin@example.com"]
    "#;

    fn parse(extra: &str) -> Result<SmtpNotifierConfig, toml::de::Error> {
        toml::from_str(&format!("{REQUIRED}\n{extra}"))
    }

    #[test]
    fn sender_defaults_to_username() {
        let config = parse(r#"username = "pulsar@example.com""#).unwrap();
        assert_eq!(config.sender.email.to_string(), "pulsar@example.com");
        assert_eq!(config.port, 465);
    }

    #[test]
    fn sender_overrides_username() {
        let config = parse(
            r#"
            username = "login-name"
            sender = "pulsar@example.com"
            "#,
        )
        .unwrap();
        assert_eq!(config.sender.email.to_string(), "pulsar@example.com");
    }

    #[test]
    fn username_must_be_an_email_without_a_sender() {
        let err = parse(r#"username = "login-name""#).unwrap_err();
        assert!(err.to_string().contains("`sender` must be set"));
    }

    #[test]
    fn empty_receivers_are_rejected() {
        let err = toml::from_str::<SmtpNotifierConfig>(
            r#"
            server = "smtp.example.com"
            username = "pulsar@example.com"
            password = "secret"
            receivers = []
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn encryption_parses_from_lowercase() {
        let config = parse(
            r#"
            username = "pulsar@example.com"
            encryption = "starttls"
            "#,
        )
        .unwrap();
        assert!(matches!(config.encryption, Encryption::StartTls));
    }
}
