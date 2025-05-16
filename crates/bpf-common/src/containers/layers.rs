use std::{
    fmt,
    fs::{self, File},
    io::BufReader,
    path::{Path, PathBuf},
    str::FromStr,
};

use bytes::Buf;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyperlocal::{UnixClientExt, UnixConnector, Uri as HyperlocalUri};
use nix::unistd::Uid;
use serde::Deserialize;

use super::ContainerError;

const DOCKER_SOCKET: &str = "/var/run/docker.sock";

/// Docker API response for `image inspect` request.
#[derive(Debug, Deserialize)]
struct ImageInspect {
    #[serde(rename = "GraphDriver")]
    graph_driver: GraphDriver,
}

#[derive(Debug, Deserialize)]
struct GraphDriver {
    #[serde(rename = "Data")]
    data: Option<GraphDriverData>,
    #[serde(rename = "Name")]
    name: GraphDriverName,
}

#[derive(Debug, Deserialize)]
struct GraphDriverData {
    #[serde(rename = "LowerDir")]
    lower_dir: Option<String>,
    #[serde(rename = "MergedDir")]
    merged_dir: Option<PathBuf>,
    #[serde(rename = "UpperDir")]
    upper_dir: Option<PathBuf>,
    #[serde(rename = "WorkDir")]
    work_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
enum GraphDriverName {
    #[serde(rename = "btrfs")]
    Btrfs,
    #[serde(rename = "fuse-overlayfs")]
    FuseOverlayfs,
    #[serde(rename = "overlay2")]
    Overlayfs,
    #[serde(rename = "vfs")]
    Vfs,
    #[serde(rename = "zfs")]
    Zfs,
}

#[derive(Debug, Deserialize)]
struct LibpodLayer {
    id: String,
    parent: Option<String>,
}

impl fmt::Display for GraphDriverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Btrfs => write!(f, "btrfs"),
            Self::FuseOverlayfs => write!(f, "fuse-overlayfs"),
            Self::Overlayfs => write!(f, "overlay2"),
            Self::Vfs => write!(f, "vfs"),
            Self::Zfs => write!(f, "zfs"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ImageDbEntry {
    rootfs: Rootfs,
}

#[derive(Debug, Deserialize)]
struct Rootfs {
    diff_ids: Vec<String>,
}

/// Returns a list of layer paths for the given Docker image ID.
pub(crate) async fn docker_layers(image_id: &str) -> Result<Vec<PathBuf>, ContainerError> {
    let client: Client<UnixConnector, Full<Bytes>> = Client::unix();
    let uri = HyperlocalUri::new(DOCKER_SOCKET, &format!("/images/{image_id}/json"));
    let uri: hyper::Uri = uri.into();

    let response =
        client
            .get(uri.clone())
            .await
            .map_err(|source| ContainerError::HyperRequest {
                source,
                uri: Box::new(uri.clone()),
            })?;
    let body_bytes = response
        .collect()
        .await
        .map_err(|source| ContainerError::HyperResponse {
            source,
            uri: uri.clone(),
        })?
        .aggregate();

    let response: ImageInspect = serde_json::from_reader(body_bytes.reader())
        .map_err(|source| ContainerError::ParseResponse { source, uri })?;

    match response.graph_driver.name {
        GraphDriverName::Btrfs => docker_btrfs_layers(image_id),
        GraphDriverName::Overlayfs => docker_overlayfs_layers(response.graph_driver.data),
        _ => {
            log::warn!(
                "Docker graph driver {} is unsupported",
                response.graph_driver.name
            );
            Ok(Vec::new())
        }
    }
}

/// Returns a list of BTRFS layer paths for the given Docker image ID.
///
/// The procedure for BTRFS is not straigthforward, since the `image inspect`
/// response doesn't have direct information about layer directories. It
/// consists of the following steps:
///
/// 1. Using the given image ID, find an "imagedb entry". It's located in
///    `/var/lib/docker/image/btrfs/imagedb/content/sha256/<image_id>`.
/// 2. Get the list of layer checksums from that entry.
/// 3. For each layer, check whether a "layerdb entry" exists. It's located
///    in `/var/lib/docker/image/btrfs/layerdb/sha256/<layer_id>`. The
///    layerdb directory contains a `cache-id` file.
/// 4. That `cache-id` file contains an ID of a BTRFS subvolume. The
///    subvolume can be found in `/var/lib/docker/btrfs/subvolumes/<cache_id>`.
fn docker_btrfs_layers(image_id: &str) -> Result<Vec<PathBuf>, ContainerError> {
    const DOCKER_IMAGEDB_PATH: &str = "/var/lib/docker/image/btrfs/imagedb/content/sha256/";
    const DOCKER_LAYERDB_PATH: &str = "/var/lib/docker/image/btrfs/layerdb/sha256/";
    const DOCKER_BTRFS_SUBVOL_PATH: &str = "/var/lib/docker/btrfs/subvolumes/";

    let mut layers = Vec::new();

    let path = PathBuf::from(DOCKER_IMAGEDB_PATH).join(image_id);
    let file = File::open(&path).map_err(|source| ContainerError::ReadFile {
        source,
        path: path.clone(),
    })?;

    let reader = BufReader::new(file);
    let imagedb_entry: ImageDbEntry = serde_json::from_reader(reader)
        .map_err(|source| ContainerError::ParseConfigFile { source, path })?;

    for layer_id in imagedb_entry.rootfs.diff_ids {
        let layer_id = layer_id
            .split(':')
            .next_back()
            .ok_or(ContainerError::InvalidLayerID(layer_id.clone()))?;

        let path = PathBuf::from(DOCKER_LAYERDB_PATH).join(layer_id);
        if path.exists() {
            let path = path.join("cache-id");
            let btrfs_subvol_id = fs::read_to_string(&path)
                .map_err(|source| ContainerError::ReadFile { source, path })?;
            let btrfs_subvol_path = PathBuf::from(DOCKER_BTRFS_SUBVOL_PATH).join(btrfs_subvol_id);

            layers.push(btrfs_subvol_path);
        }
    }

    Ok(layers)
}

fn docker_overlayfs_layers(
    graph_driver_data: Option<GraphDriverData>,
) -> Result<Vec<PathBuf>, ContainerError> {
    let mut layers = Vec::new();

    if let Some(graph_driver_data) = graph_driver_data {
        if let Some(lower_dirs) = graph_driver_data.lower_dir {
            for lower_dir in lower_dirs.split(':') {
                // `PathBuf::from_str` is infallible.
                layers.push(PathBuf::from_str(lower_dir).unwrap());
            }
        }
        if let Some(merged_dir) = graph_driver_data.merged_dir {
            layers.push(merged_dir);
        }
        if let Some(upper_dir) = graph_driver_data.upper_dir {
            layers.push(upper_dir);
        }
        if let Some(work_dir) = graph_driver_data.work_dir {
            layers.push(work_dir);
        }
    }

    Ok(layers)
}

/// For the given `top_layer`, return a vector which contains that layer and
/// all parents of it. In other words, return a vector of all layers associated
/// with an image.
pub(crate) fn podman_layers<P: AsRef<Path>>(
    top_layer_id: &str,
    uid: Uid,
    user_home: P,
) -> Result<Vec<PathBuf>, ContainerError> {
    let layer_store_path =
        find_layer_store(uid, &user_home).ok_or(ContainerError::LayerStoreNotFound)?;
    let layer_store_file =
        File::open(&layer_store_path).map_err(|source| ContainerError::ReadFile {
            source,
            path: layer_store_path.clone(),
        })?;
    let reader = BufReader::new(layer_store_file);

    let overlay_dir =
        find_overlay_dir(uid, &user_home).ok_or(ContainerError::OverlayDirNotFound)?;

    let mut layers = find_subdirs(overlay_dir.join(top_layer_id));
    let config_layers: Vec<LibpodLayer> =
        serde_json::from_reader(reader).map_err(|source| ContainerError::ParseConfigFile {
            source,
            path: layer_store_path.clone(),
        })?;
    let mut layer_id = top_layer_id;
    let mut limit = config_layers.len();
    loop {
        let pos = config_layers[..limit]
            .iter()
            .rev()
            .position(|layer| layer.id == layer_id)
            .ok_or(ContainerError::LayerNotFound(layer_id.to_string()))?;
        let layer = &config_layers[pos];
        layers.extend(find_subdirs(overlay_dir.join(&layer.id)));
        match layer.parent {
            Some(ref parent) => {
                layer_id = parent;
                limit = pos;
            }
            None => break,
        }
    }

    Ok(layers)
}

fn find_layer_store<P: AsRef<Path>>(uid: Uid, user_home: P) -> Option<PathBuf> {
    const LIBPOD_LAYER_STORE_PATH: &str = "/var/lib/containers/storage/overlay-layers/layers.json";

    let layer_store_path = if uid.is_root() {
        PathBuf::from(LIBPOD_LAYER_STORE_PATH)
    } else {
        user_home
            .as_ref()
            .join(".local")
            .join("share")
            .join("containers")
            .join("storage")
            .join("overlay-layers")
            .join("layers.json")
    };

    if !layer_store_path.exists() {
        return None;
    }

    Some(layer_store_path)
}

fn find_overlay_dir<P: AsRef<Path>>(uid: Uid, user_home: P) -> Option<PathBuf> {
    const OVERLAY_PATH: &str = "/var/lib/containers/storage/overlay";

    let overlay_dir = if uid.is_root() {
        PathBuf::from(OVERLAY_PATH)
    } else {
        user_home
            .as_ref()
            .join(".local")
            .join("share")
            .join("containers")
            .join("storage")
            .join("overlay")
    };

    if !overlay_dir.exists() {
        return None;
    }

    Some(overlay_dir)
}

/// Returns all subdirectories of the given `parent_path`.
fn find_subdirs<P: AsRef<Path>>(parent_path: P) -> Vec<PathBuf> {
    let mut subdirectories = Vec::new();

    if parent_path.as_ref().is_dir() {
        if let Ok(entries) = fs::read_dir(parent_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    subdirectories.push(path);
                }
            }
        }
    }

    subdirectories
}
