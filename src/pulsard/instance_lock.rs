use std::{
    fs::{File, OpenOptions, TryLockError},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use anyhow::{Result, anyhow, bail};

const INSTANCE_LOCK_PATH: &str = "/var/run/pulsar.lock";

/// Exclusive lock keeping a single pulsard running on the machine.
///
/// All instances share the eBPF state in `/sys/fs/bpf`, so a second one must
/// stop before loading any probe. The kernel releases the lock if pulsard dies.
/// It covers the instances sharing `/var/run`, a pulsard in a container with
/// its own `/var/run` isn't detected.
/// The lock file itself is never removed: unlinking it would let two processes
/// lock different files.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    pub fn acquire() -> Result<Self> {
        Self::acquire_at(Path::new(INSTANCE_LOCK_PATH))
    }

    fn acquire_at(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|err| anyhow!("Cannot open lock file {}: {err}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => bail!("Another pulsard is already running"),
            Err(TryLockError::Error(err)) => bail!("Cannot lock {}: {err}", path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    #[test]
    fn second_instance_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.lock");
        let _lock = InstanceLock::acquire_at(&path).unwrap();

        assert!(InstanceLock::acquire_at(&path).is_err());
    }

    #[test]
    fn lock_is_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.lock");
        drop(InstanceLock::acquire_at(&path).unwrap());

        InstanceLock::acquire_at(&path).unwrap();
    }

    #[test]
    fn concurrent_starts_lock_once() {
        const STARTS: usize = 16;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pulsar.lock");

        let barrier = Arc::new(Barrier::new(STARTS));
        let starts: Vec<_> = (0..STARTS)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    InstanceLock::acquire_at(&path)
                })
            })
            .collect();
        // Keep the winner's lock alive while checking.
        let locked: Vec<_> = starts
            .into_iter()
            .filter_map(|start| start.join().unwrap().ok())
            .collect();

        assert_eq!(locked.len(), 1);
    }
}
