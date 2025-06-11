use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

use anyhow::Context;
use pulsar_core::{
    event::Threat,
    pdk::{ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, SimplePulsarModule},
};

pub struct DesktopNotifierModule;

impl SimplePulsarModule for DesktopNotifierModule {
    type Config = Config;
    type State = ();

    const MODULE_NAME: &'static str = "desktop-notifier";
    const DEFAULT_ENABLED: bool = false;

    async fn init_state(
        &self,
        _config: &Self::Config,
        _ctx: &ModuleContext,
    ) -> Result<Self::State, ModuleError> {
        Ok(())
    }

    async fn on_event(
        event: &Event,
        config: &Self::Config,
        _state: &mut Self::State,
        _ctx: &ModuleContext,
    ) -> Result<(), ModuleError> {
        handle_event(config, event).await;
        Ok(())
    }
}

/// Check if the given event is a threat which should be notified to the user
async fn handle_event(config: &Config, event: &Event) {
    if let Some(Threat {
        source,
        description,
        extra: _,
    }) = &event.header().threat
    {
        let payload = event.payload();
        let title = format!("Pulsar module {source} identified a threat");
        let body = format!("{description}\n Source event: {payload}");
        notify_send(config, vec![title, body]).await;
    }
}

/// Send a desktop notification spawning `notify-send` with the provided arguments
async fn notify_send(config: &Config, args: Vec<String>) {
    let mut command = Command::new(&config.notify_send_executable);
    command
        .args(args)
        .env("DISPLAY", &config.display)
        .env("DBUS_SESSION_BUS_ADDRESS", &config.bus_address)
        .uid(config.user_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    tokio::spawn(async {
        let r = tokio::task::spawn_blocking(move || {
            let result = command
                .spawn()
                .context("Error spawning notify-send")?
                .wait_with_output()
                .context("Error waiting for notify-send to complete")?;
            if !result.status.success() {
                anyhow::bail!(
                    "notify-send exited with code {:?}\nStdout: {:?}\nStderr: {:?}\n",
                    result.status.code(),
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr),
                );
            }
            Ok(())
        })
        .await
        .context("Unexpected error spawning background notify task");
        match r {
            Ok(Ok(())) => {}
            Ok(Err(err)) | Err(err) => log::error!("Error sending desktop notification: {err:?}"),
        }
    });
}

#[derive(Clone)]
pub struct Config {
    user_id: u32,
    display: String,
    notify_send_executable: String,
    bus_address: String,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let user_id = config.optional("user_id")?.unwrap_or(1000);
        Ok(Self {
            user_id,
            display: config.optional("display")?.unwrap_or(":0".to_string()),
            notify_send_executable: config
                .optional("notify_send_executable")?
                .unwrap_or("notify-send".to_string()),
            bus_address: config
                .optional("bus_address")?
                .unwrap_or(format!("unix:path=/run/user/{user_id}/bus")),
        })
    }
}
