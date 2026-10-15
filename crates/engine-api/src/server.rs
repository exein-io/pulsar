use std::{
    io::ErrorKind,
    os::unix::{fs::FileTypeExt, net::UnixListener as StdUnixListener},
};

use anyhow::{Result, anyhow, bail};
use axum::{
    Json, Router,
    extract::{
        Path, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
    routing::{get, post},
};
use pulsar_core::{
    bus::Bus,
    pdk::{ModuleOverview, PulsarDaemonHandle},
};
use socket2::{Domain, SockAddr, Socket, Type};
use tokio::{net::UnixListener, sync::oneshot, task::JoinHandle};

use crate::error::EngineApiError;

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

/// The bound API socket, see [`bind_api_socket`].
pub struct ApiSocket {
    socket_path: String,
    listener: StdUnixListener,
}

/// Bind the API socket, replacing one left behind by a pulsard that didn't
/// shut down cleanly.
///
/// The caller must make sure no other pulsard is starting, e.g. by holding its
/// instance lock. A running one is detected anyway, as it's listening on the
/// socket. Bind before loading any probe, so a socket problem stops pulsard
/// before it touches the eBPF state.
pub fn bind_api_socket(custom_socket_path: Option<&str>) -> Result<ApiSocket> {
    let socket_path = custom_socket_path.unwrap_or(super::DEFAULT_UDS).to_string();
    remove_stale_socket(&socket_path)?;
    let listener = StdUnixListener::bind(&socket_path)
        .map_err(|err| anyhow!("Cannot bind to socket {socket_path}: {err}"))?;
    Ok(ApiSocket {
        socket_path,
        listener,
    })
}

/// Remove the socket left behind by a process that didn't shut down cleanly,
/// which would make the bind fail and the daemon unable to restart. Only a
/// socket nobody listens on is removed.
fn remove_stale_socket(socket_path: &str) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(socket_path) {
        Ok(metadata) => metadata,
        // Nothing to clean up.
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => bail!("Cannot inspect socket {socket_path}: {err}"),
    };
    if !metadata.file_type().is_socket() {
        // Not ours to remove, let the bind report it.
        return Ok(());
    }

    if is_listening(socket_path)? {
        bail!("Socket {socket_path} is in use by another process");
    }

    log::warn!("Removing stale socket {socket_path}");
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => bail!("Cannot remove stale socket {socket_path}: {err}"),
    }
}

/// Whether a process is listening on the socket, without blocking.
///
/// Only a refused connection proves the socket is stale: a full accept queue
/// means it's in use, and any other failure is reported as an error.
fn is_listening(socket_path: &str) -> Result<bool> {
    let check = || -> std::io::Result<bool> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&SockAddr::unix(socket_path)?) {
            Ok(()) => Ok(true),
            // The accept queue is full.
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(true),
            Err(err) if err.raw_os_error() == Some(libc::EINPROGRESS) => Ok(true),
            Err(err) if err.kind() == ErrorKind::ConnectionRefused => Ok(false),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    };
    check().map_err(|err| anyhow!("Cannot check socket {socket_path}: {err}"))
}

#[derive(Clone)]
pub struct EngineAPIContext {
    pub bus: Bus,
    pub pulsar_daemon: PulsarDaemonHandle,
}

pub fn run_api_server(
    engine_api_ctx: EngineAPIContext,
    api_socket: ApiSocket,
) -> Result<ServerHandle> {
    let modules = Router::new()
        .route("/", get(modules))
        .route("/{module_name}/start", post(module_start))
        .route("/{module_name}/restart", post(module_restart))
        .route("/{module_name}/stop", post(module_stop));

    let app = Router::new()
        .nest("/modules", modules)
        .route("/monitor", get(event_monitor_handler))
        .with_state(engine_api_ctx);

    let ApiSocket {
        socket_path,
        listener,
    } = api_socket;
    listener.set_nonblocking(true)?;
    let uds = UnixListener::from_std(listener)?;
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

#[cfg(test)]
mod tests {
    use std::{os::unix::net::UnixStream as StdUnixStream, sync::mpsc, thread, time::Duration};

    use super::*;

    #[test]
    fn stale_socket_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");
        drop(StdUnixListener::bind(&path).unwrap());

        let _api_socket = bind_api_socket(path.to_str()).unwrap();
        StdUnixStream::connect(&path).unwrap();
    }

    #[test]
    fn socket_in_use_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");
        // Like a running pulsard
        let _api_socket = bind_api_socket(path.to_str()).unwrap();

        assert!(bind_api_socket(path.to_str()).is_err());
        StdUnixStream::connect(&path).unwrap();
    }

    #[test]
    fn full_accept_queue_counts_as_listening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");
        let address = SockAddr::unix(&path).unwrap();
        // The shortest accept queue, to fill it with a couple of connections
        let listener = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
        listener.bind(&address).unwrap();
        listener.listen(0).unwrap();

        // Fill the accept queue of a listener that never accepts
        let mut clients = Vec::new();
        loop {
            let client = Socket::new(Domain::UNIX, Type::STREAM, None).unwrap();
            client.set_nonblocking(true).unwrap();
            match client.connect(&address) {
                Ok(()) => clients.push(client),
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => panic!("unexpected connect error: {err}"),
            }
        }

        // A blocking check would hang here
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(is_listening(path.to_str().unwrap())).unwrap());
        let listening = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(listening.unwrap());
    }

    #[test]
    fn other_files_fail_the_bind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");
        // Like Docker creating a missing bind mount source
        std::fs::create_dir(&path).unwrap();

        assert!(bind_api_socket(path.to_str()).is_err());
        assert!(path.is_dir());
    }

    #[test]
    fn other_files_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");
        std::fs::write(&path, "not a socket").unwrap();

        remove_stale_socket(path.to_str().unwrap()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn missing_socket_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.sock");

        remove_stale_socket(path.to_str().unwrap()).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn metadata_error_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, "").unwrap();

        // A regular file used as a directory fails with ENOTDIR, not NotFound
        let path = file.join("pulsar.sock");
        assert!(remove_stale_socket(path.to_str().unwrap()).is_err());
    }
}
