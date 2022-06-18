//! Utility functions used to extract data from procfs

use glob::glob;
use nix::unistd::{Pid, Uid};
use std::{
    fs::{self, File},
    io::{self, prelude::*, BufReader},
    path::PathBuf,
};
use thiserror::Error;

// Special value used to indicate openat should use the current working directory.
const AT_FDCWD: i32 = -100;

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
    read_link(&format!("/proc/{}/exe", pid))
}

/// Returns the current working directory of given process.
pub fn get_process_cwd(pid: Pid) -> Result<PathBuf, ProcfsError> {
    read_link(&format!("/proc/{}/cwd", pid))
}

/// Returns the current working directory of given process.
pub fn get_process_fd_path(pid: Pid, fd: i32) -> Result<PathBuf, ProcfsError> {
    if fd == AT_FDCWD {
        return get_process_cwd(pid);
    }
    read_link(&format!("/proc/{}/fd/{}", pid, fd))
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
    let path = format!("/proc/{}/cmdline", pid);
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
    let path = format!("/proc/{}/comm", pid);
    let data =
        fs::read_to_string(&path).map_err(|source| ProcfsError::ReadFile { source, path })?;
    Ok(data.trim().to_owned())
}

/// Returns the parent of a given process.
pub fn get_process_parent_pid(pid: Pid) -> Result<Pid, ProcfsError> {
    let path = format!("/proc/{}/status", pid);
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
    let path = format!("/proc/{}/status", pid);
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
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let file = match File::open(&cgroup_path) {
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
