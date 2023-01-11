use std::{ffi::CString, os::unix::prelude::FileTypeExt};

use anyhow::{anyhow, bail, ensure, Context, Result};
use hyper::{Body, Method, Request, StatusCode, Uri};
use hyperlocal::{UnixClientExt, UnixConnector};
use pulsar_core::pdk::ModuleOverview;
use serde::de::DeserializeOwned;

use crate::dto::{ConfigKV, ModuleConfigKVs};

#[derive(Debug, Clone)]
pub struct EngineApiClient {
    socket: String,
    client: hyper::Client<UnixConnector, Body>,
}

impl EngineApiClient {
    pub fn new() -> Result<Self> {
        Self::unix(super::DEFAULT_UDS.to_owned())
    }

    pub fn unix(socket: String) -> Result<Self> {
        // The is a bug using Metadata in combination with OpenOption when using pulsar cli via sudo so I had to use the libc to verify the permissions
        // Probably https://stackoverflow.com/questions/71505367/no-such-a-file-or-directory-even-path-is-file-true it's a reference
        // TODO: Should be investigated

        // Check if input exists and if it is a unix socket
        match std::fs::metadata(&socket) {
            Err(err) => match err.kind() {
                std::io::ErrorKind::NotFound => {
                    bail!("'{}' not found. Check if the daemon is running", socket)
                }
                std::io::ErrorKind::PermissionDenied => {
                    bail!("No write permission on '{}'", socket)
                }
                _ => {
                    bail!(anyhow::Error::new(err)
                        .context(format!("Failed to get '{}' metadata", socket)))
                }
            },
            Ok(metadata) => {
                ensure!(
                    metadata.file_type().is_socket(),
                    "'{}' is not a unix socket",
                    socket
                );
            }
        };

        // Check for write permission on socket
        let cstring = CString::new(socket.as_str())
            .with_context(|| format!("Can't convert '{}' to a valid string ", socket))?;
        let write_permission = unsafe { libc::access(cstring.as_ptr(), libc::W_OK) } == 0;
        ensure!(write_permission, "No write permission on '{}'", socket);

        Ok(Self {
            socket,
            client: hyper::Client::unix(),
        })
    }

    fn uri<T: AsRef<str>>(&self, path: T) -> Uri {
        hyperlocal::Uri::new(self.socket.clone(), path.as_ref()).into()
    }

    async fn get<T: DeserializeOwned>(&self, uri: Uri) -> Result<T> {
        let res = self
            .client
            .get(uri)
            .await
            .map_err(|err| anyhow!("Error during the http request: reason {}", err))?;

        let buf = hyper::body::to_bytes(res).await?;

        let output = serde_json::from_slice(&buf)?;

        Ok(output)
    }

    pub async fn list_modules(&self) -> Result<Vec<ModuleOverview>> {
        let url = self.uri("/modules");
        self.get(url).await
    }

    pub async fn get_configs(&self) -> Result<Vec<ModuleConfigKVs>> {
        let url = self.uri("/configs");
        self.get(url).await
    }

    pub async fn start(&self, module_name: &str) -> Result<()> {
        let url = self.uri(format!("/modules/{}/start", module_name));
        self.empty_post(url).await
    }

    pub async fn stop(&self, module_name: &str) -> Result<()> {
        let url = self.uri(format!("/modules/{}/stop", module_name));
        self.empty_post(url).await
    }

    pub async fn restart(&self, module_name: &str) -> Result<()> {
        let url = self.uri(format!("/modules/{}/restart", module_name));
        self.empty_post(url).await
    }

    pub async fn get_module_config(&self, module_name: &str) -> Result<Vec<ConfigKV>> {
        let url = self.uri(format!("/modules/{}/config", module_name));
        self.get(url).await
    }

    pub async fn set_module_config(
        &self,
        module_name: &str,
        config_key: String,
        config_value: String,
    ) -> Result<()> {
        let url = self.uri(format!("/modules/{}/config", module_name));

        let body_string = serde_json::to_string(&ConfigKV {
            key: config_key,
            value: config_value,
        })
        .map_err(|err| anyhow!("Error during object serialization. Reason: {err}"))?;

        let req = Request::builder()
            .method(Method::PATCH)
            .uri(url)
            .header("content-type", "application/json")
            .body(Body::from(body_string))
            .map_err(|err| anyhow!("Error building the request. Reason: {}", err))?;

        let res = self
            .client
            .request(req)
            .await
            .map_err(|err| anyhow!("Error during the http request. Reason: {}", err))?;

        let status = res.status();

        match status {
            StatusCode::OK => Ok(()),
            _ => {
                let error = hyper::body::to_bytes(res)
                    .await
                    .map_err(|err| anyhow!("Error to bytes. Reason: {}", err))?;
                let error = std::str::from_utf8(&error)
                    .map_err(|err| anyhow!("Cannot parse error str. Reason: {}", err))?;
                Err(anyhow!("Error during request. {error}"))
            }
        }
    }

    async fn empty_post(&self, uri: Uri) -> Result<()> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(Body::empty())
            .map_err(|err| anyhow!("Error building the request. Reason: {}", err))?;

        let res = self
            .client
            .request(req)
            .await
            .map_err(|err| anyhow!("Error during the http request. Reason: {}", err))?;

        let status = res.status();

        match status {
            StatusCode::OK => Ok(()),
            _ => {
                let error = hyper::body::to_bytes(res)
                    .await
                    .map_err(|err| anyhow!("Error to bytes. Reason: {}", err))?;
                let error = std::str::from_utf8(&error)
                    .map_err(|err| anyhow!("Cannot parse error str. Reason: {}", err))?;
                Err(anyhow!("Error during request. {error}"))
            }
        }
    }
}
