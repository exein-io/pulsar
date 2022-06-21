use bpf_common::{
    parsing::procfs::{self, ProcfsError},
    Pid,
};
use thiserror::Error;

/// ProcessTree contains information about all running processes
pub(crate) struct ProcessTree {
    processes: Vec<ProcessData>,
}

pub(crate) struct ProcessData {
    pub(crate) pid: Pid,
    pub(crate) image: String,
    pub(crate) parent: Pid,
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("loading process {pid}: process not found")]
    ProcessNotFound { pid: Pid },
    #[error("loading process {pid}: parent image {ppid} not found")]
    ParentNotFound { pid: Pid, ppid: Pid },
}

impl ProcessTree {
    /// Construct the `ProcessTree` by reading from `procfs`:
    /// - process list
    /// - parent pid
    /// - image
    pub(crate) fn load_from_procfs() -> Result<Self, ProcfsError> {
        let mut processes: Vec<ProcessData> = procfs::get_running_processes()?
            .into_iter()
            .map(|pid| {
                let image = procfs::get_process_image(pid)
                    .map(|path| path.to_string_lossy().to_string())
                    .unwrap_or_else(|err| {
                        log::debug!("{}", err);
                        String::new()
                    });
                let parent = procfs::get_process_parent_pid(pid).unwrap_or_else(|err| {
                    log::debug!("Error getting parent pid of {pid}: {}", err);
                    Pid::from_raw(1)
                });
                ProcessData { pid, image, parent }
            })
            .collect();
        // Make sure to add PID 0 (which is part of kernel) to map_interest to avoid
        // warnings about missing entries.
        processes.push(ProcessData {
            pid: Pid::from_raw(0),
            image: String::from("kernel"),
            parent: Pid::from_raw(0),
        });
        // TODO: we may have no parent_result if more than `/proc/sys/kernel/pid_max`
        // processes have already spawn and the pid number restarted from 0.
        // We should build a proper tree structure and do a breath first search.
        processes.sort_by_key(|p| p.pid);
        Ok(Self { processes })
    }

    /// Add a new entry and return its process info.
    /// This is needed during initialization to go from raw fork/exec events to
    /// the full PorcessData needed by the policy filtering setup.
    pub(crate) fn fork(&mut self, pid: Pid, ppid: Pid) -> Result<&ProcessData, Error> {
        let parent = self.processes.iter().find(|p| p.pid == ppid);
        match parent {
            Some(parent) => {
                let image = parent.image.to_string();
                self.processes.push(ProcessData {
                    pid,
                    image,
                    parent: ppid,
                });
                Ok(self.processes.last().unwrap())
            }
            None => Err(Error::ParentNotFound { pid, ppid }),
        }
    }

    pub(crate) fn exec(&mut self, pid: Pid, image: &str) -> Result<&ProcessData, Error> {
        match self.processes.iter().position(|p| p.pid == pid) {
            Some(i) => {
                self.processes[i].image = image.to_string();
                Ok(&self.processes[i])
            }
            None => Err(Error::ProcessNotFound { pid }),
        }
    }
}

impl<'a> IntoIterator for &'a ProcessTree {
    type Item = &'a ProcessData;
    type IntoIter = std::slice::Iter<'a, ProcessData>;
    fn into_iter(self) -> Self::IntoIter {
        self.processes.iter()
    }
}
