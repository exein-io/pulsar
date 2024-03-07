use anyhow::{anyhow, Context, Result};
use aya::{include_bytes_aligned, programs::Lsm, Btf, EbpfLoader};

/// Check if the system supports eBPF LSM programs.
/// The kernel must be build with CONFIG_BPF_LSM=y, which is available
/// since 5.7. This functionality should also be enabled, either at kernel
/// compile time or in the `--lsm=` boot flags.
/// `cat /sys/kernel/security/lsm` will list `bpf` on supported systems.
///
/// Since this could give false positives on some architectures, we'll also
/// try to load a test LSM program.
///
/// NOTE: this function is blocking.
pub fn lsm_supported() -> bool {
    match try_load() {
        Ok(()) => true,
        Err(err) => {
            if log::log_enabled!(log::Level::Debug) {
                log::warn!("LSM not supported: {err:?}");
            } else {
                log::warn!("LSM not supported: {err}");
            }

            false
        }
    }
}

const PATH: &str = "/sys/kernel/security/lsm";
static TEST_LSM_PROBE: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/test_lsm.5_13.bpf.o"));

fn try_load() -> Result<()> {
    // Check if LSM enabled
    std::fs::read_to_string(PATH)
        .with_context(|| format!("Reading {PATH} failed"))?
        .split(',')
        .any(|lsm_subsystem| lsm_subsystem == "bpf")
        .then_some(())
        .ok_or_else(|| anyhow!("eBPF LSM programs disabled"))?;

    // Check if we can load a program
    let mut bpf = EbpfLoader::new()
        .load(TEST_LSM_PROBE)
        .context("LSM enabled, but initial loading failed")?;
    let program: &mut Lsm = bpf
        .program_mut("socket_bind")
        .context("LSM program not found")?
        .try_into()
        .context("LSM program of the wrong type")?;
    let btf = Btf::from_sys_fs().context("Loading Btf failed")?;
    program.load("socket_bind", &btf).context("Load failed")?;
    program.attach().context("Attach failed")?;
    Ok(())
}
