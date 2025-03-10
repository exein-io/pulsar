use std::{
    ffi::{CStr, OsString},
    fmt,
    fs::File,
    io::{self, BufReader},
    mem,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};

use diesel::{connection::SimpleConnection, prelude::*};
use ini::Ini;
use nix::unistd::Uid;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use validatron::Validatron;

use crate::parsing::procfs::ProcfsError;

pub mod layers;
pub mod schema;

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
    #[error("parsing response from `{uri:?}` failed")]
    ParseResponse {
        #[source]
        source: serde_json::error::Error,
        uri: hyper::Uri,
    },
    #[error("path `{path}` is non-UTF-8")]
    PathNonUtf8 { path: PathBuf },
    #[error("failed to make a request to the UNIX socket `{uri:?}`")]
    HyperRequest {
        #[source]
        source: hyper_util::client::legacy::Error,
        uri: hyper::Uri,
    },
    #[error("failed to parse a response from the UNIX socket `{uri:?}`")]
    HyperResponse {
        #[source]
        source: hyper::Error,
        uri: hyper::Uri,
    },
    #[error("could not connect to the database `{path:?}`")]
    SqliteConnection {
        #[source]
        source: ConnectionError,
        path: PathBuf,
    },
    #[error("could not find libpod container `{id}`")]
    ContainerNotFound { id: String },
    #[error("could not find libpod image store")]
    ImageStoreNotFound,
    #[error("could not find libpod layer store")]
    LayerStoreNotFound,
    #[error("could not find container image `{id}` in `{path:?}`")]
    ImageNotFound { id: String, path: PathBuf },
    #[error("parsing image digest {digest} failed")]
    ParseDigest { digest: String },
    #[error("invalid hash function {hash_fn}")]
    InvalidHashFunction { hash_fn: String },
    #[error(transparent)]
    Procfs(#[from] ProcfsError),
    #[error("error parsing libpod configuration from {path}")]
    LibpodConfParsing {
        #[source]
        source: ini::Error,
        path: PathBuf,
    },
    #[error("unknown libpod database backend {0}")]
    UnknownLibpodDatabase(String),
    #[error("home directory not found for user with uid: {uid}")]
    HomeDirNotFound { uid: Uid },
    #[error("podman db `{0}` not found")]
    LibpodDBNotFound(String),
    #[error("bolt db `{0}` open failed")]
    BoltDBOpenFailed(String),
    #[error("bolt bucket `{0}` not found")]
    BoltBucketNotFound(String),
    #[error("bolt key `{0}` not found")]
    BoltKeyNotFound(String),
    #[error("Invalid layer ID: `{0}`")]
    InvalidLayerID(String),
    #[error("Invalid image digest: `{0}`")]
    InvalidImageDigest(String),
    #[error("layer {0} not found in the layer store")]
    LayerNotFound(String),
    #[error("could not find overlay directory")]
    OverlayDirNotFound,
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
    layer: String,
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
    #[validatron(skip)]
    pub layers: Vec<PathBuf>,
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
    pub async fn from_container_id(
        container_id: ContainerId,
        uid: Uid,
    ) -> Result<Option<Self>, ContainerError> {
        let info = match container_id {
            ContainerId::Docker(id) => Self::from_docker_id(id).await,
            ContainerId::Libpod(id) => Self::from_libpod_id(id, uid),
        };

        info.map(Some)
    }

    async fn from_docker_id(id: String) -> Result<Self, ContainerError> {
        const DOCKER_CONTAINERS_PATH: &str = "/var/lib/docker/containers";

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

        // `image_digest` has format like:
        //
        // ```
        // sha256:1d34ffeaf190be23d3de5a8de0a436676b758f48f835c3a2d4768b798c15a7f1
        // ```
        //
        // The unprefixed digest is used as an image ID.
        let image_id = image_digest
            .split(':')
            .last()
            .ok_or(ContainerError::InvalidImageDigest(image_digest.clone()))?;

        let layers = layers::docker_layers(image_id).await?;
        log::debug!("found layer filesystems for container {id}: {layers:?}");

        Ok(Self {
            id,
            name,
            image,
            image_digest,
            layers,
        })
    }

    fn from_libpod_id(id: String, uid: Uid) -> Result<Self, ContainerError> {
        let user_home = get_user_home_dir(uid).ok_or(ContainerError::HomeDirNotFound { uid })?;

        let user_home = Path::new(&user_home);

        let libpod_database_backend = LibpodDatabaseBackend::of_user(uid, user_home)?;

        let config = match libpod_database_backend {
            LibpodDatabaseBackend::Auto => {
                // From container.conf docs:
                //
                // The database backend of Podman.  Supported values are "" (default), "boltdb"
                // and "sqlite". An empty value means it will check whenever a boltdb already
                // exists and use it when it does, otherwise it will use sqlite as default
                // (e.g. new installs). This allows for backwards compatibility with older versions.
                // Please run `podman-system-reset` prior to changing the database
                // backend of an existing deployment, to make sure Podman can operate correctly.
                match boltdb_find_libpod_container_config(&id, uid, user_home) {
                    Ok(boltdb_config) => boltdb_config,
                    Err(ContainerError::LibpodDBNotFound(_)) => {
                        sqlite_find_libpod_container_config(&id, uid, user_home)?
                    }
                    Err(e) => return Err(e),
                }
            }
            LibpodDatabaseBackend::Sqlite => {
                sqlite_find_libpod_container_config(&id, uid, user_home)?
            }
            LibpodDatabaseBackend::BoltDB => {
                boltdb_find_libpod_container_config(&id, uid, user_home)?
            }
        };

        let image_store_path =
            find_image_store(uid, user_home).ok_or(ContainerError::ImageStoreNotFound)?;

        let image_store_file =
            File::open(&image_store_path).map_err(|source| ContainerError::ReadFile {
                source,
                path: image_store_path.clone(),
            })?;
        let reader = BufReader::new(image_store_file);

        let images: Vec<LibpodImageConfig> =
            serde_json::from_reader(reader).map_err(|source| ContainerError::ParseConfigFile {
                source,
                path: image_store_path.clone(),
            })?;

        let image_id = config.rootfs_image_id;

        let image = images.iter().find(|image| image.id == image_id).ok_or(
            ContainerError::ImageNotFound {
                id: image_id,
                path: image_store_path,
            },
        )?;

        let layers = layers::podman_layers(&image.layer, uid, user_home)?;
        log::debug!("found layer filesystems for container {id}: {layers:?}");

        Ok(Self {
            id,
            name: config.name,
            image: config.rootfs_image_name,
            image_digest: image.digest.clone(),
            layers,
        })
    }
}

#[derive(Debug)]
enum LibpodDatabaseBackend {
    Auto,
    Sqlite,
    BoltDB,
}

impl LibpodDatabaseBackend {
    /// From container.conf docs:
    ///
    /// Please refer to containers.conf(5) for details of all configuration options.
    /// Not all container engines implement all of the options.
    /// All of the options have hard coded defaults and these options will override
    /// the built in defaults. Users can then override these options via the command
    /// line. Container engines will read containers.conf files in up to three
    /// locations in the following order:
    ///  1. /usr/share/containers/containers.conf
    ///  2. /etc/containers/containers.conf
    ///  3. $HOME/.config/containers/containers.conf (Rootless containers ONLY)
    ///
    /// Items specified in the latter containers.conf, if they exist, override the
    /// previous containers.conf settings, or the default settings.
    ///
    /// So we are reading the configuration from the latter to the first
    fn of_user<P: AsRef<Path>>(uid: Uid, user_home: P) -> Result<Self, ContainerError> {
        if !uid.is_root() {
            let user_container_conf = user_home
                .as_ref()
                .join(".config")
                .join("containers")
                .join("containers.conf");

            if user_container_conf.exists() {
                if let Some(db_backend) = Self::from_config(user_container_conf)? {
                    return Ok(db_backend);
                }
            }
        }

        const ETC_CONTAINER_CONF: &str = "/etc/containers/containers.conf";

        let etc_container_conf = Path::new(ETC_CONTAINER_CONF);

        if etc_container_conf.exists() {
            if let Some(db_backend) = Self::from_config(etc_container_conf)? {
                return Ok(db_backend);
            }
        }

        const USR_CONTAINER_CONF: &str = "/usr/share/containers/containers.conf";

        let usr_container_conf = Path::new(USR_CONTAINER_CONF);

        if !usr_container_conf.exists() {
            return Ok(Self::Auto);
        }

        match Self::from_config(usr_container_conf)? {
            Some(db_backend) => Ok(db_backend),
            None => Ok(Self::Auto),
        }
    }

    fn from_config<P: AsRef<Path>>(config_file: P) -> Result<Option<Self>, ContainerError> {
        let container_conf = Ini::load_from_file(&config_file).map_err(|source| {
            ContainerError::LibpodConfParsing {
                source,
                path: config_file.as_ref().to_owned(),
            }
        })?;

        match container_conf.general_section().get("database_backend") {
            Some("sqlite") => Ok(Some(Self::Sqlite)),
            Some("boltdb") => Ok(Some(Self::BoltDB)),
            Some(database_backend) => Err(ContainerError::UnknownLibpodDatabase(
                database_backend.to_string(),
            )),
            None => Ok(None),
        }
    }
}

fn get_user_home_dir(uid: Uid) -> Option<OsString> {
    let amt = match unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) } {
        n if n < 0 => 512_usize,
        n => n as usize,
    };
    let mut buf = Vec::with_capacity(amt);
    let mut passwd: libc::passwd = unsafe { mem::zeroed() };
    let mut result = ptr::null_mut();
    match unsafe {
        libc::getpwuid_r(
            uid.as_raw(),
            &mut passwd,
            buf.as_mut_ptr(),
            buf.capacity(),
            &mut result,
        )
    } {
        0 if !result.is_null() => {
            let ptr = passwd.pw_dir as *const _;
            let bytes = unsafe { CStr::from_ptr(ptr).to_bytes() };
            if bytes.is_empty() {
                None
            } else {
                Some(OsStringExt::from_vec(bytes.to_vec()))
            }
        }
        _ => None,
    }
}

fn sqlite_find_libpod_container_config<P: AsRef<Path>>(
    container_id: &str,
    uid: Uid,
    user_home: P,
) -> Result<LibpodConfig, ContainerError> {
    const LIBPOD_SQLITE_ROOT_PATH: &str = "/var/lib/containers/storage/db.sql";

    let db_path = if uid.is_root() {
        PathBuf::from(LIBPOD_SQLITE_ROOT_PATH)
    } else {
        user_home
            .as_ref()
            .join(".local")
            .join("share")
            .join("containers")
            .join("storage")
            .join("db.sql")
    };

    if !db_path.exists() {
        return Err(ContainerError::LibpodDBNotFound(
            db_path.display().to_string(),
        ));
    }

    use schema::libpod_db_container_config::dsl::*;

    let db_path_str = db_path.to_str().ok_or(ContainerError::PathNonUtf8 {
        path: db_path.clone(),
    })?;
    let mut conn = SqliteConnection::establish(db_path_str).map_err(|source| {
        ContainerError::SqliteConnection {
            source,
            path: db_path.to_owned(),
        }
    })?;

    // Enable busy timeout to before querying the database because
    // of possible ongoing transactions
    if let Err(err) = conn
        .batch_execute("PRAGMA busy_timeout = 200;")
        .map_err(ConnectionError::CouldntSetupConfiguration)
    {
        log::error!("failed to setup busy timeout in sqlite: {err}");

        return Err(ContainerError::ContainerNotFound {
            id: container_id.to_owned(),
        });
    };

    match libpod_db_container_config
        .filter(id.eq(&container_id))
        .limit(1)
        .select(LibpodDBContainerConfig::as_select())
        .first(&mut conn)
    {
        Ok(config) => {
            let config: LibpodConfig = serde_json::from_str(&config.json).map_err(|source| {
                ContainerError::ParseConfigDB {
                    source,
                    path: db_path,
                }
            })?;

            Ok(config)
        }
        Err(e) => {
            log::error!("error querying podman sqlite database {e}");
            Err(ContainerError::ContainerNotFound {
                id: container_id.to_owned(),
            })
        }
    }
}

fn boltdb_find_libpod_container_config<P: AsRef<Path>>(
    container_id: &str,
    uid: Uid,
    user_home: P,
) -> Result<LibpodConfig, ContainerError> {
    const LIBPOD_BOLTDB_ROOT_PATH: &str = "/var/lib/containers/storage/libpod/bolt_state.db";

    let db_path = if uid.is_root() {
        PathBuf::from(LIBPOD_BOLTDB_ROOT_PATH)
    } else {
        user_home
            .as_ref()
            .join(".local")
            .join("share")
            .join("containers")
            .join("storage")
            .join("libpod")
            .join("bolt_state.db")
    };

    if !db_path.exists() {
        return Err(ContainerError::LibpodDBNotFound(
            db_path.display().to_string(),
        ));
    }

    let db = nut::DBBuilder::new(&db_path)
        .read_only(true)
        .build()
        .map_err(|_| ContainerError::BoltDBOpenFailed(db_path.display().to_string()))?;

    let tx = db.begin_tx().unwrap();

    let ctr = tx
        .bucket(b"ctr")
        .map_err(|_| ContainerError::BoltBucketNotFound("ctr".to_string()))?;

    let container_associated_bucket = ctr
        .bucket(container_id.as_bytes())
        .ok_or(ContainerError::BoltBucketNotFound(container_id.to_string()))?;

    let config = container_associated_bucket
        .get(b"config")
        .ok_or(ContainerError::BoltKeyNotFound("config".to_string()))?;

    let config: LibpodConfig =
        serde_json::from_slice(config).map_err(|source| ContainerError::ParseConfigDB {
            source,
            path: db_path,
        })?;

    Ok(config)
}

fn find_image_store<P: AsRef<Path>>(uid: Uid, user_home: P) -> Option<PathBuf> {
    const LIBPOD_IMAGE_STORE_PATH: &str = "/var/lib/containers/storage/overlay-images/images.json";

    let image_store_path = if uid.is_root() {
        PathBuf::from(LIBPOD_IMAGE_STORE_PATH)
    } else {
        user_home
            .as_ref()
            .join(".local")
            .join("share")
            .join("containers")
            .join("storage")
            .join("overlay-images")
            .join("images.json")
    };

    if !image_store_path.exists() {
        return None;
    }

    Some(image_store_path)
}
