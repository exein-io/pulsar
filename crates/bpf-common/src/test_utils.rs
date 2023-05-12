use std::path::PathBuf;

use rand::random;
use which::which;

/// Create a random file name with the given prefix
pub fn random_name(prefix: &str) -> String {
    format!("{}_{}", prefix, random::<u32>())
}

/// Resolve full path of the requested command
pub fn find_executable(cmd: &str) -> PathBuf {
    which(cmd).unwrap()
}

pub mod cgroup {
    use std::{os::unix::prelude::MetadataExt, process::exit, thread::sleep, time::Duration};

    use cgroups_rs::cgroup_builder::CgroupBuilder;
    use nix::{
        sys::signal::{kill, Signal::SIGKILL},
        unistd::{fork, ForkResult, Pid},
    };

    /// Create a cgroup v2 with the given name and return its inode number
    pub fn temp_cgroup(name: String) -> u64 {
        let hierarchy = cgroups_rs::hierarchies::V2::new();
        let cg = CgroupBuilder::new(&name)
            .build(Box::new(hierarchy))
            .expect("Error creating cgroup");
        // the cgroup id the the inode of the directory in cgroupfs
        let id = std::fs::metadata(format!("/sys/fs/cgroup/{name}"))
            .expect("Error reading cgroup inode")
            .ino();
        cg.delete().expect("Error deleting cgroup");
        id
    }

    /// Spawn a child process in a temporary cgroup with the given name.
    /// Return the child process pid and the cgroup id.
    pub fn fork_in_temp_cgroup(name: &str) -> (Pid, u64) {
        // - Create a cgroup
        let hierarchy = cgroups_rs::hierarchies::V2::new();
        let cg = CgroupBuilder::new(&name)
            .build(Box::new(hierarchy))
            .expect("Error creating cgroup");
        let id = std::fs::metadata(format!("/sys/fs/cgroup/{name}"))
            .expect("Error reading cgroup inode")
            .ino();

        // - Spawn a child process
        let child_pid = match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                sleep(Duration::from_secs(1));
                exit(0);
            }
            ForkResult::Parent { child } => child,
        };

        // - Attach it to the Cgroup
        cg.add_task_by_tgid((child_pid.as_raw() as u64).into())
            .expect("Could not attach child do cgroup");

        // - Kill the child process
        _ = kill(child_pid, SIGKILL);
        nix::sys::wait::waitpid(child_pid, None).unwrap();

        // - Destroy the cgroup
        cg.delete().expect("Error deleting cgroup");

        (child_pid, id)
    }
}
