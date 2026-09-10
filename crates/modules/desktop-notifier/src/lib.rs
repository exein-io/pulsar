use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};

use anyhow::Context;
use pulsar_core::{
    event::Threat,
    pdk::{Event, ModuleContext, ModuleError, SimplePulsarModule},
};
use serde::Deserialize;

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
        .env("DBUS_SESSION_BUS_ADDRESS", config.bus_address())
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

#[derive(Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Id of the user running the target desktop environment.
    user_id: u32,
    /// Display the notification is sent to.
    display: String,
    /// Executable used to send the notification.
    notify_send_executable: String,
    /// Address of the target session bus. Defaults to the bus of `user_id`.
    bus_address: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            user_id: 1000,
            display: ":0".to_string(),
            notify_send_executable: "notify-send".to_string(),
            bus_address: None,
        }
    }
}

impl Config {
    fn bus_address(&self) -> String {
        self.bus_address
            .clone()
            .unwrap_or_else(|| format!("unix:path=/run/user/{}/bus", self.user_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_keys_keep_defaults() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.user_id, 1000);
        assert_eq!(config.display, ":0");
        assert_eq!(config.notify_send_executable, "notify-send");
        assert_eq!(config.bus_address(), "unix:path=/run/user/1000/bus");
    }

    #[test]
    fn bus_address_follows_user_id() {
        let config: Config = toml::from_str("user_id = 1001").unwrap();
        assert_eq!(config.bus_address(), "unix:path=/run/user/1001/bus");
    }

    #[test]
    fn explicit_bus_address_wins() {
        let config: Config = toml::from_str(r#"bus_address = "unix:path=/custom""#).unwrap();
        assert_eq!(config.bus_address(), "unix:path=/custom");
    }
}
