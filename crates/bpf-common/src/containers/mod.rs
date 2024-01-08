use std::{
    fmt,
    fs::File,
    io::{self, BufRead, BufReader},
    path::PathBuf,
};

use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::Validatron;

pub mod schema;

const ETC_PASSWD: &str = "/etc/passwd";
const DOCKER_CONTAINERS_PATH: &str = "/var/lib/docker/containers";
const LIBPOD_DB_ROOT_PATH: &str = "/var/lib/containers/storage/db.sql";
const LIBPOD_IMAGE_STORE_PATH: &str = "/var/lib/containers/storage/overlay-images/images.json";

#[derive(Error, Debug)]
pub enum ContainerError {
    #[error("reading file {path:?} failed")]
    ReadFile {
        #[source]
        source: io::Error,
        path: PathBuf,
    },
    #[error("parsing config from database `{path:?}`")]
    ParseConfigDB {
        #[source]
        source: serde_json::error::Error,
        path: PathBuf,
    },
    #[error("parsing config from file `{path:?}` failed")]
    ParseConfigFile {
        #[source]
        source: serde_json::error::Error,
        path: PathBuf,
    },
    #[error("path `{path}` is non-UTF-8")]
    PathNonUtf8 { path: PathBuf },
    #[error("could not connect to the database `{path:?}`")]
    DatabaseConnection {
        #[source]
        source: ConnectionError,
        path: PathBuf,
    },
    #[error("could not find libpod container `{id}`")]
    ContainerNotFound { id: String },
    #[error("could not find container image `{id}` in `{path:?}`")]
    ImageNotFound { id: String, path: PathBuf },
    #[error("parsing image digest {digest} failed")]
    ParseDigest { digest: String },
    #[error("invalid hash function {hash_fn}")]
    InvalidHashFunction { hash_fn: String },
}

/// A container ID.
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

/// JSON configuration of Docker containers.
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

/// JSON configuration of libpod (podman, cri-o) containers.
#[derive(Debug, Deserialize)]
struct LibpodConfig {
    name: String,
    #[serde(rename = "rootfsImageID")]
    rootfs_image_id: String,
    #[serde(rename = "rootfsImageName")]
    rootfs_image_name: String,
}

/// JSON configuration of libpod (podman, cri-o) images.
#[derive(Debug, Deserialize)]
struct LibpodImageConfig {
    id: String,
    digest: String,
}

/// Database schema of libpod.
#[derive(Queryable, Selectable)]
#[diesel(table_name = schema::libpod_db_container_config)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
struct LibpodDBContainerConfig {
    json: String,
}

/// Container information used in Pulsar alerts and rules.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, Validatron)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_digest: String,
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

impl ContainerInfo {
    pub fn from_container_id(id: ContainerId) -> Result<Self, ContainerError> {
        match id {
            ContainerId::Docker(id) => {
                let path = PathBuf::from(DOCKER_CONTAINERS_PATH)
                    .join(&id)
                    .join("config.v2.json");
                let file = File::open(&path).map_err(|source| ContainerError::ReadFile {
                    source,
                    path: path.clone(),
                })?;

                let reader = BufReader::new(file);
                let config: DockerConfig = serde_json::from_reader(reader)
                    .map_err(|source| ContainerError::ParseConfigFile { source, path })?;

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
            ContainerId::Libpod(container_id) => {
                let (db_config, db_path, image_store_path) = find_libpod_container(&container_id)?;
                let config: LibpodConfig =
                    serde_json::from_str(&db_config.json).map_err(|source| {
                        ContainerError::ParseConfigDB {
                            source,
                            path: db_path,
                        }
                    })?;
                let image_id = config.rootfs_image_id;

                let image_store_file =
                    File::open(&image_store_path).map_err(|source| ContainerError::ReadFile {
                        source,
                        path: image_store_path.clone(),
                    })?;
                let reader = BufReader::new(image_store_file);

                let images: Vec<LibpodImageConfig> =
                    serde_json::from_reader(reader).map_err(|source| {
                        ContainerError::ParseConfigFile {
                            source,
                            path: image_store_path.clone(),
                        }
                    })?;
                let image = images.iter().find(|image| image.id == image_id).ok_or(
                    ContainerError::ImageNotFound {
                        id: image_id,
                        path: image_store_path,
                    },
                )?;

                Ok(Self {
                    id: container_id,
                    name: config.name,
                    image: config.rootfs_image_name,
                    image_digest: image.digest.clone(),
                })
            }
        }
    }
}

fn find_libpod_container(
    container_id: &str,
) -> Result<(LibpodDBContainerConfig, PathBuf, PathBuf), ContainerError> {
    for (db_path, image_store_path) in find_existing_libpod_files()? {
        if let Some(container) = find_libpod_container_in_db(&container_id, &db_path)? {
            return Ok((container, db_path, image_store_path));
        }
    }

    Err(ContainerError::ContainerNotFound {
        id: container_id.to_owned(),
    })
}

fn find_existing_libpod_files() -> Result<Vec<(PathBuf, PathBuf)>, ContainerError> {
    let mut db_files = Vec::new();

    let db_root_path = PathBuf::from(LIBPOD_DB_ROOT_PATH);
    let image_store_root_path = PathBuf::from(LIBPOD_IMAGE_STORE_PATH);
    if db_root_path.exists() && image_store_root_path.exists() {
        db_files.push((db_root_path, image_store_root_path));
    }

    let file = File::open(ETC_PASSWD).map_err(|source| ContainerError::ReadFile {
        source,
        path: PathBuf::from(ETC_PASSWD),
    })?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line.unwrap();
        if let Some(home_dir) = get_home_directory(&line) {
            let db_path = PathBuf::from(&home_dir).join(".local/share/containers/storage/db.sql");
            if db_path.exists() {
                let image_store_path = PathBuf::from(home_dir)
                    .join(".local/share/containers/storage/overlay-images/images.json");
                if !image_store_path.exists() {
                    continue;
                }

                db_files.push((db_path, image_store_path));
            }
        }
    }

    Ok(db_files)
}

fn get_home_directory(passwd_line: &str) -> Option<String> {
    let parts: Vec<&str> = passwd_line.split(':').collect();
    match parts.get(5) {
        Some(&"/") | Some(&"/root") => None,
        Some(home_dir) => Some(home_dir.to_string()),
        None => None,
    }
}

fn find_libpod_container_in_db(
    container_id: &str,
    db_path: &PathBuf,
) -> Result<Option<LibpodDBContainerConfig>, ContainerError> {
    use schema::libpod_db_container_config::dsl::*;

    let db_path_str = db_path.to_str().ok_or(ContainerError::PathNonUtf8 {
        path: db_path.clone(),
    })?;
    let mut conn = SqliteConnection::establish(db_path_str).map_err(|source| {
        ContainerError::DatabaseConnection {
            source,
            path: db_path.to_owned(),
        }
    })?;

    match libpod_db_container_config
        .filter(id.eq(&container_id))
        .limit(1)
        .select(LibpodDBContainerConfig::as_select())
        .first(&mut conn)
    {
        Ok(config) => Ok(Some(config)),
        Err(_) => Ok(None),
    }
}
