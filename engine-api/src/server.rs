use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use axum::{
    extract::{Extension, Path},
    routing::{get, patch, post},
    BoxError, Json, Router,
};
use futures::ready;
use hyper::server::accept::Accept;
use pulsar_core::pdk::{ModuleOverview, PulsarDaemonHandle};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::oneshot,
    task::JoinHandle,
};

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

pub struct EngineAPIContext {
    pub pulsar_daemon: PulsarDaemonHandle,
}

#[derive(serde::Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_socket_path")]
    api_socket_path: String,
}

fn default_socket_path() -> String {
    super::DEFAULT_UDS.to_string()
}

pub fn run_api_server(
    engine_api_ctx: EngineAPIContext,
    config: ServerConfig,
) -> Result<ServerHandle> {
    let modules = Router::new()
        .route("/", get(modules))
        .route("/:module_name/start", post(module_start))
        .route("/:module_name/restart", post(module_restart))
        .route("/:module_name/stop", post(module_stop))
        .route("/:module_name/config", get(get_module_cfg))
        .route("/:module_name/config", patch(update_module_cfg));

    let app = Router::new()
        .nest("/modules", modules)
        .route("/configs", get(configs))
        .layer(Extension(Arc::new(engine_api_ctx)));

    let uds = UnixListener::bind(&config.api_socket_path)
        .map_err(|err| anyhow!("Cannot bind to socket: {err}"))?;
    log::debug!("listening on {}", config.api_socket_path);

    let (tx_shutdown, rx_shutdown) = oneshot::channel();

    let server = axum::Server::builder(ServerAccept { uds })
        .serve(app.into_make_service())
        .with_graceful_shutdown(async move {
            let _ = rx_shutdown.await;
        });

    let server_join_handle = tokio::spawn(async move {
        if let Err(e) = server.await {
            log::error!("Engine Api server error: {}", e);
        }
        if let Err(e) = tokio::fs::remove_file(config.api_socket_path).await {
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
    Extension(ctx): Extension<Arc<EngineAPIContext>>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.start(module_name).await?;
    Ok(())
}

async fn module_restart(
    Extension(ctx): Extension<Arc<EngineAPIContext>>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.restart(module_name).await?;
    Ok(())
}

async fn module_stop(
    Extension(ctx): Extension<Arc<EngineAPIContext>>,
    Path(module_name): Path<String>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon.stop(module_name).await?;
    Ok(())
}

async fn modules(Extension(ctx): Extension<Arc<EngineAPIContext>>) -> Json<Vec<ModuleOverview>> {
    Json(ctx.pulsar_daemon.modules().await)
}

async fn configs(Extension(ctx): Extension<Arc<EngineAPIContext>>) -> Json<Vec<ModuleConfigKVs>> {
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
    Extension(ctx): Extension<Arc<EngineAPIContext>>,
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
    Extension(ctx): Extension<Arc<EngineAPIContext>>,
    Path(module_name): Path<String>,
    Json(config_kv): Json<ConfigKV>,
) -> Result<(), EngineApiError> {
    ctx.pulsar_daemon
        .update_configuration(module_name, config_kv.key, config_kv.value)
        .await?;
    Ok(())
}

struct ServerAccept {
    uds: UnixListener,
}

impl Accept for ServerAccept {
    type Conn = UnixStream;
    type Error = BoxError;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let (stream, _addr) = ready!(self.uds.poll_accept(cx))?;
        Poll::Ready(Some(Ok(stream)))
    }
}
