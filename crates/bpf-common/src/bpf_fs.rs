use anyhow::{bail, Context, Result};
use procfs::process::{MountInfo, Process};
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;
use sys_mount::{Mount, MountFlags};

const BPF_FS_PATH: &str = "/sys/fs/bpf";
const BPF: &str = "bpf";

pub fn check_or_mount_bpf_fs() -> Result<()> {
    if current_bpf_fs()?.is_none() {
        mount_bpf_fs()?;
    }
    if has_multiple_bpf_fs_mount()? {
        bail!("Multiple bpf fs mounts detected")
    }
    Ok(())
}

fn current_bpf_fs() -> Result<Option<MountInfo>> {
    let p_self = Process::myself().context("Error accessing /proc/self")?;
    let mount_info = p_self
        .mountinfo()
        .context("Error accessing process mount info")?;
    for mount in mount_info {
        if mount.mount_point == Path::new(BPF_FS_PATH) {
            if mount.fs_type == BPF {
                return Ok(Some(mount));
            }
            bail!("File system {BPF_FS_PATH} is mounted but with type {BPF}")
        }
    }

    Ok(None)
}

fn mount_bpf_fs() -> Result<()> {
    let bpf_fs_path = Path::new(BPF_FS_PATH);

    if !bpf_fs_path.exists() {
        log::debug!("Create '{BPF_FS_PATH}' because is not found");

        DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(BPF_FS_PATH)
            .with_context(|| format!("Error creating {BPF_FS_PATH}"))?;
    }
    if !bpf_fs_path.is_dir() {
        bail!("'{BPF_FS_PATH}' already exists and is not a directory")
    }

    log::debug!("Mount BPF file system");

    Mount::new(
        BPF,
        BPF_FS_PATH,
        sys_mount::FilesystemType::Manual(BPF),
        MountFlags::empty(),
        None,
    )
    .context("Failed to mount BPF file system")?;

    Ok(())
}

fn has_multiple_bpf_fs_mount() -> Result<bool> {
    let p_self = Process::myself().context("Error accessing /proc/self")?;
    let mount_info = p_self
        .mountinfo()
        .context("Error accessing process mount info")?;

    let bpf_fs_path = Path::new(BPF_FS_PATH);
    let num_bpf_fs = mount_info
        .iter()
        .filter(|mount| mount.root == "/" && mount.mount_point == bpf_fs_path)
        .count();

    Ok(num_bpf_fs > 1)
}
