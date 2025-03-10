use anyhow::{Result, anyhow};
use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
    routing::{get, patch, post},
};
use pulsar_core::{
    bus::Bus,
    pdk::{ModuleOverview, PulsarDaemonHandle},
};
use tokio::{net::UnixListener, sync::oneshot, task::JoinHandle};

use crate::{
    dto::{ConfigKV, ModuleConfigKVs},
    error::EngineApiError,
};

pub struct ServerHandle {
    tx_shutdown: oneshot::Sender<()>,
    server_join_handle: JoinHandle<()>,
}

impl ServerHandle {
    pub async fn stop(self) {
        drop(self.tx_shutdown);
        let _ = self.server_join_handle.await;
    }
}

#[derive(Clone)]
pub struct EngineAPIContext {
    pub bus: Bus,
    pub pulsar_daemon: PulsarDaemonHandle,
}

pub fn run_api_server(
    engine_api_ctx: EngineAPIContext,
    custom_socket_path: Option<&str>,
) -> Result<ServerHandle> {
    let modules = Router::new()
        .route("/", get(modules))
        .route("/{module_name}/start", post(module_start))
        .route("/{module_name}/restart", post(module_restart))
        .route("/{module_name}/stop", post(module_stop))
        .route("/{module_name}/config", get(get_module_cfg))
        .route("/{module_name}/config", patch(update_module_cfg));

    let app = Router::new()
        .nest("/modules", modules)
        .route("/configs", get(configs))
        .route("/monitor", get(event_monitor_handler))
        .with_state(engine_api_ctx);

    let socket_path = custom_socket_path.unwrap_or(super::DEFAULT_UDS).to_string();

    let uds =
        UnixListener::bind(&socket_path).map_err(|err| anyhow!("Cannot bind to socket: {err}"))?;
    log::debug!("listening on {}", socket_path);

    let (tx_shutdown, rx_shutdown) = oneshot::channel();

    let server = axum::serve(uds, app).with_graceful_shutdown(async move {
        let _ = rx_shutdown.await;
    });

    let server_join_handle = tokio::spawn(async move {
        if let Err(e) = server.await {
            log::error!("Engine Api server error: {}", e);
        }
        if let Err(e) = tokio::fs::remove_file(socket_path).await {
            log::error!("Error removing unix socket: {}", e);
        };
    });

    let server_handle = ServerHandle {
        tx_shutdown,
        server_join_handle,
    };

    Ok(server_handle)
}

async fn module_start(
    State(ctx): State<EngineAPIContext>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.start(module_name).await?;
    Ok(())
}

async fn module_restart(
    State(ctx): State<EngineAPIContext>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.restart(module_name).await?;
    Ok(())
}

async fn module_stop(
    State(ctx): State<EngineAPIContext>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.stop(module_name).await?;
    Ok(())
}

async fn modules(State(ctx): State<EngineAPIContext>) -> Json<Vec<ModuleOverview>> {
    Json(ctx.pulsar_daemon.modules().await)
}

async fn configs(State(ctx): State<EngineAPIContext>) -> Json<Vec<ModuleConfigKVs>> {
    let cfgs = ctx.pulsar_daemon.get_configurations().await;

    let cfgs_key_value: Vec<_> = cfgs
        .into_iter()
        .map(|(module, cfg)| {
            let config: Vec<_> = cfg
                .into_iter()
                .map(|(key, value)| ConfigKV { key, value })
                .collect();

            ModuleConfigKVs { module, config }
        })
        .collect();

    Json(cfgs_key_value)
}

async fn get_module_cfg(
    State(ctx): State<EngineAPIContext>,
    Path(module_name): Path<String>,
) -> Result<Json<Vec<ConfigKV>>, EngineApiError> {
    let cfg = ctx.pulsar_daemon.get_configuration(module_name).await?;

    let cfg_key_value: Vec<_> = cfg
        .into_iter()
        .map(|(key, value)| ConfigKV { key, value })
        .collect();

    Ok(Json(cfg_key_value))
}

async fn update_module_cfg(
    State(ctx): State<EngineAPIContext>,
    Path(module_name): Path<String>,
    Json(config_kv): Json<ConfigKV>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon
        .update_configuration(module_name, config_kv.key, config_kv.value)
        .await?;
    Ok(())
}

async fn event_monitor_handler(
    State(ctx): State<EngineAPIContext>,
    ws: WebSocketUpgrade,
) -> Response {
    let mut bus_receiver = ctx.bus.get_receiver();

    // This closure reads events from the bus receiver and sends them into the socket
    let handle_socket = |mut socket: WebSocket| async move {
        loop {
            match pulsar_core::pdk::receive_from_broadcast(&mut bus_receiver, "engine_api").await {
                Ok(event) => match serde_json::to_string(&*event) {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            // client disconnected
                            return;
                        }
                    }
                    Err(e) => {
                        log::error!("error occurred in event serialization: {e}");
                        return;
                    }
                },
                Err(e) => {
                    log::error!("error reading from the bus: {e}");
                    return;
                }
            }
        }
    };

    ws.on_upgrade(handle_socket)
}
