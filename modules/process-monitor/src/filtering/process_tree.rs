use std::{collections::HashMap, io::Read};

use bpf_common::{
    parsing::procfs::{self, ProcfsError},
    Pid,
};
use thiserror::Error;

/// ProcessTree contains information about all running processes
pub(crate) struct ProcessTree {
    processes: Vec<ProcessData>,
}

#[derive(Debug)]
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

pub(crate) const PID_0: Pid = Pid::from_raw(0);

impl ProcessTree {
    /// Construct the `ProcessTree` by reading from `procfs`:
    /// - process list
    /// - parent pid
    /// - image
    pub(crate) fn load_from_procfs() -> Result<Self, ProcfsError> {
        let mut processes: HashMap<Pid, ProcessData> = HashMap::new();
        let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
        let mut sorted_processes: Vec<ProcessData> = Vec::new();

        // Get process list
        for pid in procfs::get_running_processes()? {
            let task_path = format!("/proc/{}/task", pid);
            
            let tasks = std::fs::read_dir(&task_path);
            if tasks.is_err() {
                continue;
            }
            for entry in tasks.unwrap() {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    let _task_path = format!("/proc/{}/task/{}", pid, path.to_string_lossy().into_owned());
                    let task_status = format!("/proc/{}/task/{}/status", pid, path.to_string_lossy().into_owned());
                    let proc_task_status = std::fs::File::open(&task_status);
                    if proc_task_status.is_err() {
                        continue;
                    }
                    let mut buffer = vec![];
                    proc_task_status.unwrap().read_to_end(&mut buffer).unwrap();
                    
                    procfs::parse_proc_task_status(&buffer, task_status);

                    // get_container_id_from_task_dir(&task_path);
                } else {
                    ProcfsError::ReadFile {
                        source: entry.err().unwrap(),
                        path: task_path.clone(),
                    };
                }                

            }
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
            processes.insert(pid, ProcessData { pid, image, parent });
            children.entry(parent).or_default().push(pid);
        }

        // Make sure to add PID 0 (which is part of kernel) to map_interest to avoid
        // warnings about missing entries.
        processes.insert(
            PID_0,
            ProcessData {
                pid: PID_0,
                image: String::from("kernel"),
                parent: PID_0,
            },
        );

        // Sort process tree by starting by process 0
        fn add_process_and_children(
            pid: Pid,
            processes: &mut HashMap<Pid, ProcessData>,
            children: &mut HashMap<Pid, Vec<Pid>>,
            sorted_processes: &mut Vec<ProcessData>,
        ) {
            let process = processes.remove(&pid).unwrap();
            sorted_processes.push(process);
            for child in children.remove(&pid).unwrap_or_default() {
                add_process_and_children(child, processes, children, sorted_processes);
            }
        }
        add_process_and_children(PID_0, &mut processes, &mut children, &mut sorted_processes);
        if !processes.is_empty() {
            log::warn!("Found processes not starting from root: {:?}", processes);
            sorted_processes.extend(processes.into_values());
        }

        Ok(Self {
            processes: sorted_processes,
        })
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
