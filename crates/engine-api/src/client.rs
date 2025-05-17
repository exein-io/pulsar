use std::{ffi::CString, os::unix::prelude::FileTypeExt};

use futures::{Stream, StreamExt};
use http_body_util::{BodyExt, Either, Empty, Full};
use hyper::body::{Buf, Bytes};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector};
use pulsar_core::pdk::{Event, ModuleOverview};
use serde::de::DeserializeOwned;
use tokio_tungstenite::{client_async, tungstenite::Message};

use crate::{
    dto::{ConfigKV, ModuleConfigKVs},
    error::{EngineClientError, WebsocketError},
};

#[derive(Debug, Clone)]
pub struct EngineApiClient {
    socket: String,
    client: Client<UnixConnector, Either<Full<Bytes>, Empty<Bytes>>>,
}

impl EngineApiClient {
    pub fn new() -> Result<Self, EngineClientError> {
        Self::unix(super::DEFAULT_UDS.to_owned())
    }

    pub fn unix(socket: String) -> Result<Self, EngineClientError> {
        // The is a bug using Metadata in combination with OpenOption when using pulsar cli via sudo so I had to use the libc to verify the permissions
        // Probably https://stackoverflow.com/questions/71505367/no-such-a-file-or-directory-even-path-is-file-true it's a reference
        // TODO: Should be investigated

        // Check if input exists and if it is a unix socket
        match std::fs::metadata(&socket) {
            Err(err) => {
                return match err.kind() {
                    std::io::ErrorKind::NotFound => Err(EngineClientError::SocketNotFound(socket)),
                    std::io::ErrorKind::PermissionDenied => {
                        Err(EngineClientError::NoReadPermission(socket))
                    }
                    _ => Err(EngineClientError::FailedToGetMetadata(socket)),
                };
            }
            Ok(metadata) => {
                if !metadata.file_type().is_socket() {
                    return Err(EngineClientError::NotASocket(socket));
                }
            }
        };

        // Check for write permission on socket
        let cstring = match CString::new(socket.as_str()) {
            Ok(cs) => cs,
            Err(err) => return Err(EngineClientError::CStringConversion(err)),
        };

        let write_permission = unsafe { libc::access(cstring.as_ptr(), libc::W_OK) } == 0;
        if !write_permission {
            return Err(EngineClientError::NoWritePermission(socket));
        }

        Ok(Self {
            socket,
            client: Client::unix(),
        })
    }

    fn uri<T: AsRef<str>>(&self, path: T) -> Uri {
        hyperlocal::Uri::new(self.socket.clone(), path.as_ref()).into()
    }

    async fn get<T: DeserializeOwned>(&self, uri: Uri) -> Result<T, EngineClientError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Either::Right(Empty::<Bytes>::new()))
            .map_err(EngineClientError::RequestBuilderError)?;

        let res = self
            .client
            .request(req)
            .await
            .map_err(EngineClientError::HyperError)?;

        let status = res.status();

        match status.is_success() {
            true => {
                let buf = res
                    .collect()
                    .await
                    .map_err(EngineClientError::CollectResponseError)?
                    .aggregate();

                let output = serde_json::from_reader(buf.reader())
                    .map_err(|err| EngineClientError::DeserializeError(err.to_string()))?;

                Ok(output)
            }
            false => {
                let error = res
                    .collect()
                    .await
                    .map_err(EngineClientError::CollectResponseError)?
                    .to_bytes();

                let error_str =
                    std::str::from_utf8(&error).map_err(EngineClientError::Utf8Error)?;

                Err(EngineClientError::UnexpectedResponse(format!(
                    "HTTP error {}: {}",
                    status.as_u16(),
                    error_str
                )))
            }
        }
    }

    pub async fn list_modules(&self) -> Result<Vec<ModuleOverview>, EngineClientError> {
        let url = self.uri("/modules");
        self.get(url).await
    }

    pub async fn get_configs(&self) -> Result<Vec<ModuleConfigKVs>, EngineClientError> {
        let url = self.uri("/configs");
        self.get(url).await
    }

    pub async fn start(&self, module_name: &str) -> Result<(), EngineClientError> {
        let url = self.uri(format!("/modules/{module_name}/start"));
        self.empty_post(url).await
    }

    pub async fn stop(&self, module_name: &str) -> Result<(), EngineClientError> {
        let url = self.uri(format!("/modules/{module_name}/stop"));
        self.empty_post(url).await
    }

    pub async fn restart(&self, module_name: &str) -> Result<(), EngineClientError> {
        let url = self.uri(format!("/modules/{module_name}/restart"));
        self.empty_post(url).await
    }

    pub async fn get_module_config(
        &self,
        module_name: &str,
    ) -> Result<Vec<ConfigKV>, EngineClientError> {
        let url = self.uri(format!("/modules/{module_name}/config"));
        self.get(url).await
    }

    pub async fn set_module_config(
        &self,
        module_name: &str,
        config_key: String,
        config_value: String,
    ) -> Result<(), EngineClientError> {
        let url = self.uri(format!("/modules/{module_name}/config"));

        let body_string = serde_json::to_string(&ConfigKV {
            key: config_key,
            value: config_value,
        })
        .map_err(|err| EngineClientError::SerializeError(err.to_string()))?;

        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url)
            .header("content-type", "application/json")
            .body(Either::Left(Full::from(body_string)))
            .map_err(EngineClientError::RequestBuilderError)?;

        let res = self
            .client
            .request(req)
            .await
            .map_err(EngineClientError::HyperError)?;

        let status = res.status();

        match status {
            StatusCode::OK => Ok(()),
            _ => {
                let error = res
                    .collect()
                    .await
                    .map_err(EngineClientError::CollectResponseError)?
                    .to_bytes();

                let error_str =
                    std::str::from_utf8(&error).map_err(EngineClientError::Utf8Error)?;

                Err(EngineClientError::UnexpectedResponse(error_str.to_string()))
            }
        }
    }

    async fn empty_post(&self, uri: Uri) -> Result<(), EngineClientError> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Either::Right(Empty::<Bytes>::new()))
            .map_err(EngineClientError::RequestBuilderError)?;

        let res = self
            .client
            .request(req)
            .await
            .map_err(EngineClientError::HyperError)?;

        let status = res.status();

        match status {
            StatusCode::OK => Ok(()),
            _ => {
                let error = res
                    .collect()
                    .await
                    .map_err(EngineClientError::CollectResponseError)?
                    .to_bytes();

                let error_str =
                    std::str::from_utf8(&error).map_err(EngineClientError::Utf8Error)?;

                Err(EngineClientError::UnexpectedResponse(error_str.to_string()))
            }
        }
    }

    pub async fn event_monitor(
        &self,
    ) -> Result<impl Stream<Item = Result<Event, WebsocketError>>, EngineClientError> {
        let stream = tokio::net::UnixStream::connect(&self.socket)
            .await
            .map_err(EngineClientError::SocketConnectionError)?;

        // The `localhost` domain is simply a placeholder for the url. It's not used because is already present a stream
        let (ws_stream, _) = client_async("ws://localhost/monitor", stream)
            .await
            .map_err(|e| EngineClientError::WebSocketError(Box::new(e)))?;

        let (_, read_stream) = ws_stream.split();

        let events_stream = read_stream.map(|item| {
            item.map_err(|err| err.into()).and_then(|msg| {
                if let Message::Text(json) = msg {
                    let event: Event =
                        serde_json::from_str(&json).map_err(WebsocketError::JsonError)?;
                    Ok(event)
                } else {
                    Err(WebsocketError::UnsupportedMessageType)
                }
            })
        });

        Ok(events_stream)
    }
}
