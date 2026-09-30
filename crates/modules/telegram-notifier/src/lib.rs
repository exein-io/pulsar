use anyhow::Context;
use pulsar_core::{
    event::Threat,
    pdk::{ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, SimplePulsarModule},
};
use reqwest::{Client, Url};
use std::time::Duration;

pub struct TelegramNotifierModule;

impl SimplePulsarModule for TelegramNotifierModule {
    type Config = Config;
    type State = TelegramNotifierState;

    const MODULE_NAME: &'static str = "telegram-notifier";
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        _config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .context("Error building reqwest client")?;
        Ok(Self::State { client })
    }

    async fn on_event(
        event: &Event,
        config: &Self::Config,
        state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        handle_event(config, event, &state.client).await;
        Ok(())
    }
}

pub struct TelegramNotifierState {
    client: Client,
}

async fn handle_event(config: &Config, event: &Event, client: &Client) {
    if let Some(Threat {
        source,
        description,
        extra: _,
    }) = &event.header().threat
    {
        let payload = event.payload();
        let text = format!(
            "Pulsar module {source} identified a threat\n\
            {description}\n Source event: {payload}",
        );
        notify_telegram(config, client, &text).await;
    }
}

async fn notify_telegram(config: &Config, client: &Client, text: &str) {
    let client = client.clone();
    let url = config.send_message_url.clone();
    let chat_id = config.chat_id.clone();
    let text = text.to_owned();
    tokio::spawn(async move {
        let response = client
            .post(url)
            .form(&[("chat_id", chat_id.as_str()), ("text", text.as_str())])
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                log::error!(
                    "Telegram API error: status={:?}, body={:?}",
                    response.status(),
                    response.text().await.unwrap_or_default(),
                );
            }
            Err(err) => {
                log::error!("Error sending Telegram notification: {err:?}");
            }
        }
    });
}

#[derive(Clone)]
pub struct Config {
    send_message_url: Url,
    chat_id: String,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let api_url = config
            .optional::<String>("api_url")?
            .unwrap_or("https://api.telegram.org".to_string());
        let base = Url::parse(api_url.as_str()).map_err(|err| ConfigError::InvalidValue {
            field: "api_url".to_string(),
            value: api_url.clone(),
            err: err.to_string(),
        })?;
        let bot_token = config.required::<String>("bot_token")?;
        let send_message_url =
            base.join(&format!("/bot{bot_token}/sendMessage"))
                .map_err(|err| ConfigError::InvalidValue {
                    field: "bot_token".to_string(),
                    value: "<redacted>".to_string(),
                    err: err.to_string(),
                })?;
        Ok(Self {
            send_message_url,
            chat_id: config.required("chat_id")?,
        })
    }
}
