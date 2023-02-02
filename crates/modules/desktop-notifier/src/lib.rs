use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::Arc,
};

use anyhow::{Context, Result};
use pulsar_core::{
    event::Threat,
    pdk::{
        CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, PulsarModule,
        ShutdownSignal, Version,
    },
};

const MODULE_NAME: &str = "desktop-notifier";

pub fn module() -> PulsarModule {
    PulsarModule::new(
        MODULE_NAME,
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap(),
        desktop_nitifier_task,
    )
}

async fn desktop_nitifier_task(
    ctx: ModuleContext,
    mut shutdown: ShutdownSignal,
) -> Result<CleanExit, ModuleError> {
    let mut receiver = ctx.get_receiver();
    let mut rx_config = ctx.get_config();
    let mut config = rx_config.read()?;

    loop {
        tokio::select! {
            r = shutdown.recv() => return r,
            _ = rx_config.changed() => {
                config = rx_config.read()?;
                continue;
            }
            msg = receiver.recv() => {
                handle_event(&config, msg?).await;
            }
        }
    }
}

/// Check if the given event is a threat which should be notified to the user
async fn handle_event(config: &Config, event: Arc<Event>) {
    if let Some(Threat { source, info }) = &event.header().threat {
        let payload = event.payload();
        let title = format!("Pulsar module {source} identified a threat");
        let body = format!("{info}\n Source event: {payload}");
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
struct Config {
    user_id: u32,
    display: String,
    notify_send_executable: String,
    bus_address: String,
}

impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let user_id = config.with_default("user_id", 1000)?;
        Ok(Self {
            user_id,
            display: config.with_default("display", ":0".to_string())?,
            notify_send_executable: config
                .with_default("notify_send_executable", "notify-send".to_string())?,
            bus_address: config
                .with_default("bus_address", format!("unix:path=/run/user/{user_id}/bus"))?,
        })
    }
}
