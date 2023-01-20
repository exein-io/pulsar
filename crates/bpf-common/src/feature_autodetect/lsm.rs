use anyhow::{anyhow, Context, Result};

/// Check if the system supports eBPF LSM programs.
/// The kernel must be build with CONFIG_BPF_LSM=y, which is available
/// since 5.7. This functionality should also be enabled, either at kernel
/// compile time or in the `--lsm=` boot flags.
/// `cat /sys/kernel/security/lsm` will list `bpf` on supported systems.
pub async fn lsm_supported() -> bool {
    match tokio::task::spawn_blocking(try_load)
        .await
        .context("Error in background task")
    {
        Ok(Ok(())) => true,
        Err(err) | Ok(Err(err)) => {
            log::warn!("LSM not supported: {:?}", err);
            false
        }
    }
}
const PATH: &str = "/sys/kernel/security/lsm";

fn try_load() -> Result<()> {
    std::fs::read_to_string(PATH)
        .with_context(|| format!("Reading {PATH} failed"))?
        .split(',')
        .any(|lsm_subsystem| lsm_subsystem == "bpf")
        .then_some(())
        .ok_or_else(|| anyhow!("eBPF LSM programs disabled"))
}
