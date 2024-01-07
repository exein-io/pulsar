use std::collections::{BTreeMap, HashMap};

use bpf_common::{
    parsing::{
        containers::{self, ContainerInfo},
        procfs::{self, ProcfsError},
    },
    time::Timestamp,
    Pid,
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    time,
};

use crate::event::Namespaces;

pub fn start_process_tracker() -> ProcessTrackerHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let mut process_tracker = ProcessTracker::new(rx);
    tokio::spawn(async move { process_tracker.run().await });
    ProcessTrackerHandle { tx }
}

#[derive(Clone)]
pub struct ProcessTrackerHandle {
    tx: mpsc::UnboundedSender<TrackerRequest>,
}

enum TrackerRequest {
    GetProcessInfo(InfoRequest),
    UpdateProcess(TrackerUpdate),
    IsDescendantOf(DescendantRequest),
}

#[derive(Debug)]
pub enum TrackerUpdate {
    Fork {
        pid: Pid,
        timestamp: Timestamp,
        ppid: Pid,
        namespaces: Namespaces,
        is_new_container: bool,
    },
    Exec {
        pid: Pid,
        timestamp: Timestamp,
        image: String,
        argv: Vec<String>,
        namespaces: Namespaces,
        is_new_container: bool,
    },
    SetNewParent {
        pid: Pid,
        ppid: Pid,
    },
    Exit {
        pid: Pid,
        timestamp: Timestamp,
    },
}

struct InfoRequest {
    pid: Pid,
    ts: Timestamp,
    tx_reply: oneshot::Sender<Result<ProcessInfo, TrackerError>>,
}

struct DescendantRequest {
    pid: Pid,
    image: String,
    tx_reply: oneshot::Sender<bool>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrackerError {
    #[error("process not found")]
    ProcessNotFound,
    #[error("process started later")]
    ProcessNotStartedYet,
    #[error("process exited")]
    ProcessExited,
}

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error(transparent)]
    Procfs(#[from] ProcfsError),
    #[error(transparent)]
    Container(#[from] containers::ContainerError),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub image: String,
    pub ppid: Pid,
    pub fork_time: Timestamp,
    pub argv: Vec<String>,
    pub namespaces: Namespaces,
    pub container: Option<ContainerInfo>,
}

impl ProcessTrackerHandle {
    pub async fn get(&self, pid: Pid, ts: Timestamp) -> Result<ProcessInfo, TrackerError> {
        let (tx_reply, rx_reply) = oneshot::channel();
        let r = self.tx.send(TrackerRequest::GetProcessInfo(InfoRequest {
            pid,
            ts,
            tx_reply,
        }));
        // ProcessTracker can only be shut down by dropping all ProcessTrackerHandle,
        // so we can unwrap the result.
        assert!(r.is_ok());
        rx_reply.await.unwrap()
    }

    pub fn update(&self, request: TrackerUpdate) {
        let r = self.tx.send(TrackerRequest::UpdateProcess(request));
        assert!(r.is_ok());
    }

    /// Check if the process with the given PID is a descendant of the given image.
    pub async fn is_descendant_of(&self, pid: Pid, image: String) -> bool {
        let (tx_reply, rx_reply) = oneshot::channel();
        let r = self
            .tx
            .send(TrackerRequest::IsDescendantOf(DescendantRequest {
                pid,
                image,
                tx_reply,
            }));
        assert!(r.is_ok());
        rx_reply.await.unwrap()
    }
}

struct ProcessTracker {
    /// commands receiver
    rx: mpsc::UnboundedReceiver<TrackerRequest>,
    /// current processes
    processes: HashMap<Pid, ProcessData>,
    /// current containers
    containers: HashMap<Namespaces, ContainerInfo>,
    /// scheduled removal of exited processes
    next_cleanup: Timestamp,
    /// pending info requests arrived before the process was created
    pending_requests: Vec<(time::Instant, InfoRequest)>,
    /// pending process updates arrived before its fork
    pending_updates: HashMap<Pid, Vec<TrackerUpdate>>,
}

#[derive(Debug)]
struct ProcessData {
    ppid: Pid,
    fork_time: Timestamp,
    exit_time: Option<Timestamp>,
    original_image: String,
    exec_changes: BTreeMap<
        Timestamp, // exec event timestamp
        String,    // new image name
    >,
    argv: Vec<String>,
    namespaces: Namespaces,
}

/// Cleanup timeout in nanoseconds. This is how long an exited process
/// is kept inside process tracker before being eligible for delete.
const CLEANUP_TIMEOUT: u64 = 5_000_000_000; // 5 seconds
/// How long to consider a process still alive after it exited. Some eBPF probes
/// might be processed after sched_process_exit, like on_tcp_set_state.
const EXIT_THRESHOLD: u64 = 5_000_000; // 5 millis

impl ProcessTracker {
    fn new(rx: mpsc::UnboundedReceiver<TrackerRequest>) -> Self {
        let mut processes = HashMap::new();
        // Some eBPF events (eg. TCP connections closed) may be reported
        // to PID 0, which is part of the kernel.
        processes.insert(
            Pid::from_raw(0),
            ProcessData {
                ppid: Pid::from_raw(0),
                fork_time: Timestamp::from(0),
                exit_time: None,
                original_image: "kernel".to_string(),
                exec_changes: BTreeMap::new(),
                argv: Vec::new(),
                namespaces: Namespaces::default(),
            },
        );
        Self {
            rx,
            processes,
            containers: HashMap::new(),
            next_cleanup: Timestamp::now() + CLEANUP_TIMEOUT,
            pending_requests: Vec::new(),
            pending_updates: HashMap::new(),
        }
    }

    async fn run(&mut self) {
        loop {
            let timeout = async {
                match self.pending_requests.first() {
                    Some(pending) => time::sleep_until(pending.0).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                msg = self.rx.recv() => match msg {
                    Some(msg) => {
                        self.handle_message(msg);
                        self.cleanup();
                        // We check pending requests here and not periodically because
                        // the only way we can get a response is by handling a message.
                        self.check_pending_requests();
                    },
                    None => break,
                },
                () = timeout => {
                    self.cancel_timed_out_requests();
                },
            }
        }
    }

    fn handle_message(&mut self, req: TrackerRequest) {
        match req {
            TrackerRequest::UpdateProcess(update) => self.handle_update(update),
            TrackerRequest::GetProcessInfo(info_request) => {
                let r = self.get_info(info_request.pid, info_request.ts);
                match r {
                    Err(TrackerError::ProcessNotFound) => {
                        // Since pulsar events are asynchronous, sometimes we may read a process event before
                        // its creation (the fork event). This would result in processes no found.
                        // We store tx_reply and check again in a certain time.
                        log::debug!("Saving pending info request for {}", info_request.pid);
                        let timeout = time::Instant::now() + time::Duration::from_millis(100);
                        self.pending_requests.push((timeout, info_request));
                    }
                    x => {
                        let _ = info_request.tx_reply.send(x);
                    }
                }
            }
            TrackerRequest::IsDescendantOf(descendant_request) => {
                let r = self.is_descendant_of(descendant_request.pid, &descendant_request.image);
                match r {
                    Err(e) => {
                        log::warn!(
                            "Error in the descendant request for {} with image {}: {:?}",
                            descendant_request.pid,
                            descendant_request.image,
                            e
                        );
                        let _ = descendant_request.tx_reply.send(false);
                    }
                    Ok(x) => {
                        let _ = descendant_request.tx_reply.send(x);
                    }
                }
            }
        }
    }

    fn handle_container_info(
        &mut self,
        pid: Pid,
        namespaces: Namespaces,
        is_new_container: bool,
    ) -> Result<(), ContainerError> {
        let container_id = procfs::get_process_container_id(pid)?;
        if let Some(id) = container_id {
            let container_info = ContainerInfo::from_container_id(id.clone())?;
            self.containers.entry(namespaces).or_insert_with(|| {
                if is_new_container {
                    log::debug!("Detected a new container {id}");
                } else {
                    log::debug!("Detected an already existing container {id}");
                }
                container_info
            });
        }
        Ok(())
    }

    fn handle_update(&mut self, mut update: TrackerUpdate) {
        match update {
            TrackerUpdate::Fork {
                pid,
                timestamp,
                ppid,
                namespaces,
                is_new_container,
            } => {
                self.handle_container_info(pid, namespaces, is_new_container)
                    .unwrap_or_else(|err| log::error!("{err}"));
                self.processes.insert(
                    pid,
                    ProcessData {
                        ppid,
                        fork_time: timestamp,
                        exit_time: None,
                        original_image: self.get_image(ppid, timestamp),
                        exec_changes: BTreeMap::new(),
                        argv: self
                            .processes
                            .get(&ppid)
                            .map(|parent| parent.argv.clone())
                            .unwrap_or_default(),
                        namespaces,
                    },
                );
                if let Some(pending_updates) = self.pending_updates.remove(&pid) {
                    pending_updates
                        .into_iter()
                        .for_each(|update| self.handle_update(update));
                }
            }
            TrackerUpdate::Exec {
                pid,
                timestamp,
                ref mut image,
                ref mut argv,
                namespaces,
                is_new_container,
            } => {
                self.handle_container_info(pid, namespaces, is_new_container)
                    .unwrap_or_else(|err| log::error!("{err}"));
                if let Some(p) = self.processes.get_mut(&pid) {
                    p.exec_changes.insert(timestamp, std::mem::take(image));
                    p.argv = std::mem::take(argv)
                } else {
                    // if exec arrived before the fork, we save the event as pending
                    log::debug!("(exec) Process {pid} not found in process tree, saving for later");
                    self.pending_updates.entry(pid).or_default().push(update);
                }
            }
            TrackerUpdate::Exit { pid, timestamp } => {
                if let Some(p) = self.processes.get_mut(&pid) {
                    p.exit_time = Some(timestamp);
                } else {
                    // if exit arrived before the fork, we save the event as pending
                    log::debug!("(exit) Process {pid} not found in process tree, saving for later");
                    self.pending_updates.entry(pid).or_default().push(update);
                }
            }
            TrackerUpdate::SetNewParent { pid, ppid } => {
                if let Some(p) = self.processes.get_mut(&pid) {
                    p.ppid = ppid;
                } else {
                    log::warn!("{ppid} is the new parent of {pid}, but we couldn't find it")
                }
            }
        }
    }

    fn get_info(&self, pid: Pid, ts: Timestamp) -> Result<ProcessInfo, TrackerError> {
        let process = self
            .processes
            .get(&pid)
            .ok_or(TrackerError::ProcessNotFound)?;
        let container: Option<ContainerInfo> = self.containers.get(&process.namespaces).cloned();
        if ts < process.fork_time {
            log::warn!(
                "{} not forked yet {} < {} ({}ms)",
                pid,
                ts,
                process.fork_time,
                (process.fork_time - ts).raw() / 1000000,
            );
            return Err(TrackerError::ProcessNotStartedYet);
        }
        if let Some(exit_time) = process.exit_time {
            if exit_time + EXIT_THRESHOLD < ts {
                log::warn!("{} exited {} < {}", pid, exit_time, ts);
                return Err(TrackerError::ProcessExited);
            }
        }
        Ok(ProcessInfo {
            image: self.get_image(pid, ts),
            ppid: process.ppid,
            fork_time: process.fork_time,
            argv: process.argv.clone(),
            namespaces: process.namespaces,
            container,
        })
    }

    /// get image name at a certain point of time
    fn get_image(&self, pid: Pid, ts: Timestamp) -> String {
        match self.processes.get(&pid) {
            Some(p) => p
                .exec_changes
                .range(..=ts)
                .next_back()
                .map(|(_timestamp, image)| image)
                .unwrap_or(&p.original_image)
                .clone(),
            None => String::new(),
        }
    }

    /// Every CLEANUP_TIMEOUT, we check all processes and remove the ones
    /// exited by more than CLEANUP_TIMEOUT.
    fn cleanup(&mut self) {
        let now = Timestamp::now();
        if now > self.next_cleanup {
            log::trace!("periodic process_tracker cleanup");
            self.processes.retain(|pid, v| match v.exit_time {
                Some(exit_time) if (now - exit_time) > CLEANUP_TIMEOUT.into() => {
                    log::trace!(
                        "deleting [{}:{:?}] from process_tracker",
                        pid,
                        v.exec_changes.iter().last()
                    );
                    false
                }
                _ => true,
            });
            self.next_cleanup = now + CLEANUP_TIMEOUT;
        }
    }

    /// Check if the response for a pending request is finally available
    fn check_pending_requests(&mut self) {
        let mut pending_requests = Vec::new();
        std::mem::swap(&mut self.pending_requests, &mut pending_requests);
        pending_requests.into_iter().for_each(|(deadline, req)| {
            let response = self.get_info(req.pid, req.ts);
            if matches!(response, Err(TrackerError::ProcessNotFound)) {
                // keep waiting
                self.pending_requests.push((deadline, req));
            } else {
                let _ = req.tx_reply.send(response);
            }
        });
    }

    /// Check the timeout of every pending request (info requests for which there
    /// was no running process at the time)
    fn cancel_timed_out_requests(&mut self) {
        let now = time::Instant::now();
        let mut pending_requests = Vec::new();
        std::mem::swap(&mut self.pending_requests, &mut pending_requests);
        pending_requests.into_iter().for_each(|(deadline, req)| {
            if now > deadline {
                let _ = req.tx_reply.send(Err(TrackerError::ProcessNotFound));
            } else {
                self.pending_requests.push((deadline, req));
            }
        });
    }

    /// Check if a PID is descendant of a target image
    fn is_descendant_of(&self, pid: Pid, target_image: &str) -> Result<bool, TrackerError> {
        let mut process = self
            .processes
            .get(&pid)
            .ok_or(TrackerError::ProcessNotFound)?;

        // Loop through the parent processes until we find the target image
        // Exit if we reach the root process
        loop {
            if process.original_image.eq(target_image)
                || process
                    .exec_changes
                    .values()
                    .any(|image| image.eq(target_image))
            {
                return Ok(true);
            }

            if process.ppid == Pid::from_raw(0) {
                return Ok(false);
            }

            process = self
                .processes
                .get(&process.ppid)
                .ok_or(TrackerError::ProcessNotFound)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID_1: Pid = Pid::from_raw(42);
    const PID_2: Pid = Pid::from_raw(43);

    const NAMESPACES_1: Namespaces = Namespaces {
        uts: 4026531835,
        ipc: 4026531839,
        mnt: 4026531841,
        pid: 4026531836,
        net: 4026531840,
        time: 4026531834,
        cgroup: 4026531838,
    };

    #[tokio::test]
    async fn no_processes_by_default() {
        let process_tracker = start_process_tracker();
        assert_eq!(
            process_tracker.get(PID_1, 0.into()).await,
            Err(TrackerError::ProcessNotFound)
        );
    }

    #[tokio::test]
    async fn different_response_depending_on_timestamp() {
        let process_tracker = start_process_tracker();
        assert_eq!(
            process_tracker.get(PID_2, 0.into()).await,
            Err(TrackerError::ProcessNotFound)
        );
        process_tracker.update(TrackerUpdate::Fork {
            ppid: PID_1,
            pid: PID_2,
            timestamp: 10.into(),
            namespaces: NAMESPACES_1,
            is_new_container: false,
        });
        process_tracker.update(TrackerUpdate::Exec {
            pid: PID_2,
            image: "/bin/after_exec".to_string(),
            timestamp: 15.into(),
            argv: Vec::new(),
            namespaces: NAMESPACES_1,
            is_new_container: false,
        });
        process_tracker.update(TrackerUpdate::Exit {
            pid: PID_2,
            timestamp: 100.into(),
        });
        time::sleep(time::Duration::from_millis(10)).await;
        assert_eq!(
            process_tracker.get(PID_2, 0.into()).await,
            Err(TrackerError::ProcessNotStartedYet)
        );
        assert_eq!(
            process_tracker.get(PID_2, 10.into()).await.unwrap(),
            ProcessInfo {
                image: String::new(),
                ppid: PID_1,
                fork_time: 10.into(),
                argv: Vec::new(),
                namespaces: NAMESPACES_1,
                container: None,
            }
        );
        assert_eq!(
            process_tracker.get(PID_2, 15.into()).await.unwrap(),
            ProcessInfo {
                image: "/bin/after_exec".to_string(),
                ppid: PID_1,
                fork_time: 10.into(),
                argv: Vec::new(),
                namespaces: NAMESPACES_1,
                container: None,
            }
        );
        assert_eq!(
            process_tracker
                .get(PID_2, (101 + EXIT_THRESHOLD).into())
                .await,
            Err(TrackerError::ProcessExited)
        );
    }

    #[tokio::test]
    async fn pending_events() {
        // on multi-core machines we could get the exec/exit events before its fork
        let process_tracker = start_process_tracker();
        process_tracker.update(TrackerUpdate::Exit {
            pid: PID_2,
            timestamp: 18.into(),
        });
        process_tracker.update(TrackerUpdate::Exec {
            pid: PID_2,
            image: "/bin/after_exec".to_string(),
            timestamp: 15.into(),
            argv: Vec::new(),
            namespaces: NAMESPACES_1,
            is_new_container: false,
        });
        process_tracker.update(TrackerUpdate::Fork {
            ppid: PID_1,
            pid: PID_2,
            timestamp: 10.into(),
            namespaces: NAMESPACES_1,
            is_new_container: false,
        });
        assert_eq!(
            process_tracker.get(PID_2, 9.into()).await,
            Err(TrackerError::ProcessNotStartedYet)
        );
        assert_eq!(
            process_tracker.get(PID_2, 13.into()).await,
            Ok(ProcessInfo {
                image: "".to_string(),
                ppid: PID_1,
                fork_time: 10.into(),
                argv: Vec::new(),
                namespaces: NAMESPACES_1,
                container: None,
            })
        );
        assert_eq!(
            process_tracker.get(PID_2, 17.into()).await,
            Ok(ProcessInfo {
                image: "/bin/after_exec".to_string(),
                ppid: PID_1,
                fork_time: 10.into(),
                argv: Vec::new(),
                namespaces: NAMESPACES_1,
                container: None,
            })
        );
        time::sleep(time::Duration::from_millis(1)).await;
        assert_eq!(
            process_tracker
                .get(PID_2, (22 + EXIT_THRESHOLD).into())
                .await,
            Err(TrackerError::ProcessExited)
        );
    }
}
