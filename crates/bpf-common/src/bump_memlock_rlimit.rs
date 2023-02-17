use anyhow::{anyhow, bail, Result};

/// Bumps the rlimit for memlock up to full capacity.
/// This is required to load even reasonably sized eBPF maps until kernel 5.11.
pub fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!(anyhow!(std::io::Error::last_os_error()).context("Failed to increase rlimit"))
    }
    Ok(())
}
