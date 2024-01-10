//! Utility functions used to extract data from procfs

use glob::glob;
use lazy_static::lazy_static;
use nix::unistd::{Pid, Uid};
use regex::Regex;
use std::{
    fs::{self, File},
    io::{self, prelude::*, BufReader},
    path::PathBuf,
};
use thiserror::Error;

use crate::containers::ContainerId;

// Special value used to indicate openat should use the current working directory.
const AT_FDCWD: i32 = -100;

lazy_static! {
    /// Pattern for matching cgroups created by Docker.
    static ref RE_CGROUP_DOCKER: Regex = Regex::new(r"docker.(?P<id>[0-9a-f]+)(?:[^0-9a-f])").unwrap();
    /// Pattern for matching cgroups created by libpod/podman.
    static ref RE_CGROUP_LIBPOD: Regex = Regex::new(r"libpod(?:-conmon)?-(?P<id>[0-9a-f]+)(?:[^0-9a-f])").unwrap();
}

#[derive(Error, Debug)]
pub enum ProcfsError {
    #[error("reading link failed {path}")]
    ReadFile {
        #[source]
        source: io::Error,
        path: String,
    },

    #[error("parent for process {0} not found")]
    ParentNotFound(Pid),
    #[error("user id for process {0} not found")]
    UserNotFound(Pid),

    #[error("globbing running processes")]
    GlobbingError(#[from] glob::PatternError),
    #[error("unreadable entry")]
    GlobError(#[from] glob::GlobError),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
}

/// Returns the path of the executable image of a given process.
pub fn get_process_image(pid: Pid) -> Result<PathBuf, ProcfsError> {
    read_link(&format!("/proc/{pid}/exe"))
}

/// Returns the current working directory of given process.
pub fn get_process_cwd(pid: Pid) -> Result<PathBuf, ProcfsError> {
    read_link(&format!("/proc/{pid}/cwd"))
}

/// Returns the current working directory of given process.
pub fn get_process_fd_path(pid: Pid, fd: i32) -> Result<PathBuf, ProcfsError> {
    if fd == AT_FDCWD {
        return get_process_cwd(pid);
    }
    read_link(&format!("/proc/{pid}/fd/{fd}"))
}

/// Return where a link is pointing to.
fn read_link(path: &str) -> Result<PathBuf, ProcfsError> {
    fs::read_link(path).map_err(|source| ProcfsError::ReadFile {
        source,
        path: path.to_string(),
    })
}

/// Convenience type for command lines.
pub type CommandLine = Vec<String>;

/// Returns the command line for the given process.
pub fn get_process_command_line(pid: Pid) -> Result<CommandLine, ProcfsError> {
    let path = format!("/proc/{pid}/cmdline");
    let data =
        fs::read_to_string(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;

    Ok(data
        .split('\0')
        .filter_map(|s| {
            if !s.is_empty() {
                Some(s.to_string())
            } else {
                None
            }
        })
        .collect())
}

/// Returns the command name for the given process.
pub fn get_process_comm(pid: Pid) -> Result<String, ProcfsError> {
    let path = format!("/proc/{pid}/comm");
    let data =
        fs::read_to_string(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;
    Ok(data.trim().to_owned())
}

/// Returns the parent of a given process.
pub fn get_process_parent_pid(pid: Pid) -> Result<Pid, ProcfsError> {
    let path = format!("/proc/{pid}/status");
    let file = File::open(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        if !line.is_empty() && line.starts_with("PPid:") {
            let mut s = line.split(':');
            let _ = s.next().unwrap();
            let value = s.next().unwrap().trim();
            return Ok(Pid::from_raw(value.parse().unwrap()));
        }
    }

    Err(ProcfsError::ParentNotFound(pid))
}

/// Returns the user id of a given process.
pub fn get_process_user_id(pid: Pid) -> Result<Uid, ProcfsError> {
    let path = format!("/proc/{pid}/status");
    let file = File::open(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        if !line.is_empty() && line.starts_with("Uid:") {
            let mut s = line.split(':');
            let _ = s.next().unwrap();
            let value = s.next().unwrap().split('\t').nth(1).unwrap().trim();
            return Ok(Uid::from_raw(value.parse().unwrap()));
        }
    }

    Err(ProcfsError::UserNotFound(pid))
}

/// Returns the cpuset cgroup id of a given process.
pub fn get_process_cgroup_id(pid: Pid) -> Option<String> {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    let file = match File::open(cgroup_path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        if !line.is_empty() && line.contains(":cpuset:") {
            let mut s = line.splitn(3, ':');
            return s.nth(2).map(|s| s.to_string());
        }
    }

    None
}

pub fn get_running_processes() -> Result<Vec<Pid>, ProcfsError> {
    glob("/proc/[0-9]*")?
        .map(|entry| {
            let entry: String = entry?.to_string_lossy().into();
            let pid = entry.replace("/proc/", "").parse()?;
            Ok(Pid::from_raw(pid))
        })
        .collect()
}

fn get_container_id_from_cgroup(cgroup_info: &str) -> Option<ContainerId> {
    if let Some(caps) = RE_CGROUP_DOCKER.captures(cgroup_info) {
        let id = caps.name("id").unwrap();
        return Some(ContainerId::Docker(id.as_str().to_string()));
    }
    if let Some(caps) = RE_CGROUP_LIBPOD.captures(cgroup_info) {
        let id = caps.name("id").unwrap();
        return Some(ContainerId::Libpod(id.as_str().to_string()));
    }
    None
}

pub fn get_process_container_id(pid: Pid) -> Result<Option<ContainerId>, ProcfsError> {
    if pid.as_raw() == 0 {
        return Ok(None);
    }

    let path = format!("/proc/{pid}/cgroup");
    let file = File::open(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;

    let reader = BufReader::new(file);
    for line in reader.lines().flatten() {
        if let Some(container_id) = get_container_id_from_cgroup(&line) {
            return Ok(Some(container_id));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_container_id_from_cgroup() {
        let container_id = get_container_id_from_cgroup("0::/init.scope");
        assert_eq!(container_id, None);

        let container_id = get_container_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-Alacritty-3266.scope");
        assert_eq!(container_id, None);

        let container_id = get_container_id_from_cgroup("0::/system.slice/docker-14467e1a5a6da17b660a130932f1ab568f35586bac8bc5147987d9bba4da08de.scope");
        assert_eq!(
            container_id,
            Some(ContainerId::Docker(
                "14467e1a5a6da17b660a130932f1ab568f35586bac8bc5147987d9bba4da08de".to_owned()
            ))
        );

        // The standard cgroup pattern observed with podman on:
        // * Gentoo
        // * openSUSE
        let container_id = get_container_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-3f084b4c7b789c1a0f174da3fcd339e31125d3096b3ff46a0bef4fad71d09362.scope/container");
        assert_eq!(
            container_id,
            Some(ContainerId::Libpod(
                "3f084b4c7b789c1a0f174da3fcd339e31125d3096b3ff46a0bef4fad71d09362".to_owned()
            ))
        );
        // The cgroup pattern observed with podman on Fedora.
        let container_id = get_container_id_from_cgroup("0::/machine.slice/libpod-conmon-551ccf517b3394d9b953efeb8296b93451e45c2a8288518e4391d7b1db3cc9ee.scope");
        assert_eq!(
            container_id,
            Some(ContainerId::Libpod(
                "551ccf517b3394d9b953efeb8296b93451e45c2a8288518e4391d7b1db3cc9ee".to_owned()
            ))
        )
    }
}
