use std::collections::HashMap;

use bpf_common::{time::Timestamp, Pid};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot},
    time,
};

#[derive(Clone)]
pub struct ProcessTrackerHandle {
    tx: mpsc::UnboundedSender<TrackerRequest>,
}

enum TrackerRequest {
    GetProcessInfo(InfoRequest),
    UpdateProcess(TrackerUpdate),
}

pub enum TrackerUpdate {
    Fork {
        pid: Pid,
        timestamp: Timestamp,
        ppid: Pid,
    },
    Exec {
        pid: Pid,
        timestamp: Timestamp,
        image: String,
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

#[derive(Debug, Error, PartialEq)]
pub enum TrackerError {
    #[error("process not found")]
    ProcessNotFound,
    #[error("process started later")]
    ProcessNotStartedYet,
    #[error("process exited")]
    ProcessExited,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ProcessInfo {
    pub image: String,
    pub ppid: Pid,
    pub fork_time: Timestamp,
}

impl ProcessTrackerHandle {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut process_tracker = ProcessTracker::new(rx);
        tokio::spawn(async move { process_tracker.run().await });
        Self { tx }
    }

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
}

impl Default for ProcessTrackerHandle {
    fn default() -> Self {
        Self::new()
    }
}

struct ProcessTracker {
    /// commands receiver
    rx: mpsc::UnboundedReceiver<TrackerRequest>,
    /// current processes
    data: HashMap<Pid, ProcessData>,
    /// scheduled removal of exited processes
    next_cleanup: Timestamp,
    /// pending info requests arrived before the process was created
    pending_requests: Vec<(time::Instant, InfoRequest)>,
}

struct ProcessData {
    ppid: Pid,
    fork_time: Timestamp,
    exit_time: Option<Timestamp>,
    original_image: String,
    exec_changes: Vec<(
        Timestamp, // exec event timestamp
        String,    // new image name
    )>,
}

/// Cleanup timeout in nanoseconds. This is how long an exited process
/// is kept inside process tracker before being eligible for delete.
const CLEANUP_TIMEOUT: u64 = 5_000_000_000; // 5 seconds
/// How long to consider a process still alive after it exited. Some eBPF probes
/// might be processed after sched_process_exit, like on_tcp_set_state.
const EXIT_THRESHOLD: u64 = 5_000_000; // 5 millis

impl ProcessTracker {
    fn new(rx: mpsc::UnboundedReceiver<TrackerRequest>) -> Self {
        let mut data = HashMap::new();
        // Some eBPF events (eg. TCP connections closed) may be reported
        // to PID 0, which is part of the kernel.
        data.insert(
            Pid::from_raw(0),
            ProcessData {
                ppid: Pid::from_raw(0),
                fork_time: Timestamp::from(0),
                exit_time: None,
                original_image: "kernel".to_string(),
                exec_changes: vec![],
            },
        );
        Self {
            rx,
            data,
            next_cleanup: Timestamp::now() + CLEANUP_TIMEOUT,
            pending_requests: Vec::new(),
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
            TrackerRequest::UpdateProcess(TrackerUpdate::Fork {
                pid,
                timestamp,
                ppid,
            }) => {
                self.data.insert(
                    pid,
                    ProcessData {
                        ppid,
                        fork_time: timestamp,
                        exit_time: None,
                        original_image: self.get_image(ppid, timestamp),
                        exec_changes: Vec::new(),
                    },
                );
                // TODO: apply self.pending_event if matching pid
            }
            TrackerRequest::UpdateProcess(TrackerUpdate::Exec {
                pid,
                timestamp,
                image,
            }) => {
                if let Some(p) = self.data.get_mut(&pid) {
                    p.exec_changes.push((timestamp, image));
                    p.exec_changes.sort_by_key(|p| p.0.raw());
                } else {
                    // if exec arrived before the fork, we save the event as pending
                    // TODO: save self.pending_event
                    log::warn!("(exec) Process {pid} not found in process tree");
                }
            }
            TrackerRequest::UpdateProcess(TrackerUpdate::Exit { pid, timestamp }) => {
                if let Some(p) = self.data.get_mut(&pid) {
                    p.exit_time = Some(timestamp);
                } else {
                    // if exit arrived before the fork, we save the event as pending
                    // TODO: save self.pending_event
                    log::warn!("(exit) Process {pid} not found in process tree");
                }
            }
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
        }
    }

    fn get_info(&self, pid: Pid, ts: Timestamp) -> Result<ProcessInfo, TrackerError> {
        let process = self.data.get(&pid).ok_or(TrackerError::ProcessNotFound)?;
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
        })
    }

    /// get image name at a certain point of time
    fn get_image(&self, pid: Pid, ts: Timestamp) -> String {
        match self.data.get(&pid) {
            Some(p) => p
                .exec_changes
                .iter()
                .rev()
                .find_map(|(exec_ts, image)| (exec_ts.raw() <= ts.raw()).then(|| image))
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
            self.data.retain(|pid, v| match v.exit_time {
                Some(exit_time) if (now - exit_time) > CLEANUP_TIMEOUT.into() => {
                    log::trace!(
                        "deleting [{}:{:?}] from process_tracker",
                        pid,
                        v.exec_changes.last()
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID_1: Pid = Pid::from_raw(42);
    const PID_2: Pid = Pid::from_raw(43);

    #[tokio::test]
    async fn no_processes_by_default() {
        let process_tracker = ProcessTrackerHandle::new();
        assert_eq!(
            process_tracker.get(PID_1, 0.into()).await,
            Err(TrackerError::ProcessNotFound)
        );
    }

    #[tokio::test]
    async fn different_response_depending_on_timestamp() {
        let process_tracker = ProcessTrackerHandle::new();
        assert_eq!(
            process_tracker.get(PID_2, 0.into()).await,
            Err(TrackerError::ProcessNotFound)
        );
        process_tracker.update(TrackerUpdate::Fork {
            ppid: PID_1,
            pid: PID_2,
            timestamp: 10.into(),
        });
        process_tracker.update(TrackerUpdate::Exec {
            pid: PID_2,
            image: "/bin/after_exec".to_string(),
            timestamp: 15.into(),
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
                fork_time: 10.into()
            }
        );
        assert_eq!(
            process_tracker.get(PID_2, 15.into()).await.unwrap(),
            ProcessInfo {
                image: "/bin/after_exec".to_string(),
                ppid: PID_1,
                fork_time: 10.into()
            }
        );
        assert_eq!(
            process_tracker
                .get(PID_2, (101 + EXIT_THRESHOLD).into())
                .await,
            Err(TrackerError::ProcessExited)
        );
    }
}
