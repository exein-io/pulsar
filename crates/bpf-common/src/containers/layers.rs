use std::{
    fmt,
    fs::{self, File},
    io::BufReader,
    path::PathBuf,
    str::FromStr,
};

use hyper::{body, Client};
use hyperlocal::{UnixClientExt, Uri as HyperlocalUri};
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
    let client = Client::unix();
    let uri = HyperlocalUri::new(DOCKER_SOCKET, &format!("/images/{}/json", image_id));
    let uri: hyper::Uri = uri.into();

    let response =
        client
            .get(uri.clone())
            .await
            .map_err(|source| ContainerError::HyperRequest {
                source,
                uri: uri.clone(),
            })?;
    let body_bytes =
        body::to_bytes(response)
            .await
            .map_err(|source| ContainerError::HyperResponse {
                source,
                uri: uri.clone(),
            })?;

    let response: ImageInspect = serde_json::from_slice(&body_bytes)
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
            .last()
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
