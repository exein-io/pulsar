use std::{
    fmt,
    fs::File,
    io::{self, BufReader},
    process::Command,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::Validatron;

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("reading file {path} failed")]
    ReadFile {
        #[source]
        source: io::Error,
        path: String,
    },
    #[error("parsing config from `{path}` failed")]
    ParseConfig {
        #[source]
        source: serde_json::error::Error,
        path: String,
    },
    #[error("executing {command} failed")]
    Exec {
        #[source]
        source: io::Error,
        command: String,
    },
    #[error("executing {command} failed with status {code:?}")]
    ExecStatus { command: String, code: Option<i32> },
    #[error("parsing image digest {digest} failed")]
    ParseDigest { digest: String },
    #[error("invalid hash function {hash_fn}")]
    InvalidHashFunction { hash_fn: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContainerId {
    Docker(String),
    Libpod(String),
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContainerId::Docker(id) => write!(f, "{id}"),
            ContainerId::Libpod(id) => write!(f, "{id}"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Config")]
    config: DockerContainerConfig,
    #[serde(rename = "Image")]
    image_digest: String,
    #[serde(rename = "Name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct DockerContainerConfig {
    #[serde(rename = "Image")]
    image: String,
}

#[derive(Debug, Deserialize)]
struct LibpodConfig {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "ImageDigest")]
    image_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Validatron)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_digest: String,
}

impl ContainerInfo {
    pub fn from_container_id(id: ContainerId) -> Result<Self, ContainerError> {
        match id {
            ContainerId::Docker(id) => {
                let path = format!("/var/lib/docker/containers/{}/config.v2.json", id);
                let file = File::open(&path).map_err(|source| ContainerError::ReadFile {
                    source,
                    path: path.clone(),
                })?;

                let reader = BufReader::new(file);
                let config: DockerConfig = serde_json::from_reader(reader)
                    .map_err(|source| ContainerError::ParseConfig { source, path })?;

                let name = config.name;
                let name = if let Some(name) = name.strip_prefix('/') {
                    name.to_owned()
                } else {
                    name
                };
                let image = config.config.image;
                let image_digest = config.image_digest;

                Ok(Self {
                    id,
                    name,
                    image,
                    image_digest,
                })
            }
            ContainerId::Libpod(id) => {
                let output = Command::new("podman")
                    .arg("inspect")
                    .arg("--type=container")
                    .arg(&id)
                    .output()
                    .map_err(|source| ContainerError::Exec {
                        source,
                        command: "podman".to_owned(),
                    })?;

                if !output.status.success() {
                    return Err(ContainerError::ExecStatus {
                        command: "podman".to_owned(),
                        code: output.status.code(),
                    });
                }

                let config: LibpodConfig =
                    serde_json::from_slice(&output.stdout).map_err(|source| {
                        ContainerError::ParseConfig {
                            source,
                            path: format!("podman inspect --type=container {id}"),
                        }
                    })?;

                let name = config.name;
                let image = config.image;
                let image_digest = config.image_digest;

                Ok(Self {
                    id,
                    name,
                    image,
                    image_digest,
                })
            }
        }
    }
}

impl fmt::Display for ContainerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ id: {}, name: {}, image: {}, image_digest: {} }}",
            self.id, self.name, self.image, self.image_digest
        )
    }
}
