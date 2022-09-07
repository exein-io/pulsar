//! [`Program`] is a wrapper around [`aya::Bpf`] which:
//! - runs background thread which sets up the probe and waits for a shutdown signal
//! - allows to read events events.
//!
use core::fmt;
use std::{mem::size_of, sync::Arc, time::Duration};

use aya::{
    maps::{
        perf::{AsyncPerfEventArray, PerfBufferError},
        HashMap, MapRefMut,
    },
    programs::{KProbe, Lsm, RawTracePoint, TracePoint},
    util::online_cpus,
    Bpf, BpfLoader, Btf, BtfError, Pod,
};
use bytes::BytesMut;
use thiserror::Error;
use tokio::{sync::watch, task::JoinError};

use crate::{time::Timestamp, BpfSender, Pid};

const PERF_HEADER_SIZE: usize = 4;
const PINNED_MAPS_PATH: &str = "/sys/fs/bpf/pulsar";

pub const PERF_PAGES_DEFAULT: usize = 4096;

/// BpfContext contains extra settings which could be provided on program load
#[derive(Clone)]
pub struct BpfContext {
    /// Enable pinning to file-system for shared maps.
    /// This should be set only for the final executable, not for tests and
    /// examples where process tracking is not running.
    pinning: Pinning,
    pinning_path: String,
    /// Btf allows to load it only once on startup
    btf: Arc<Btf>,
    /// How many pages of memory (4Kb) to use for perf arrays.
    /// NOTE: this will result in a memory usage of:
    /// (number of modules) * (number of cores) * (perf_pages) * 4Kb
    perf_pages: usize,
    /// Log level for eBPF print statements
    log_level: BpfLogLevel,
}

#[derive(Clone)]
pub enum Pinning {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy)]
pub enum BpfLogLevel {
    Disabled = 0,
    Error = 1,
    Debug = 2,
}

impl BpfContext {
    pub fn new(
        pinning: Pinning,
        mut perf_pages: usize,
        log_level: BpfLogLevel,
    ) -> Result<Self, ProgramError> {
        let btf = Btf::from_sys_fs()?;
        if perf_pages == 0 || (perf_pages & (perf_pages - 1) != 0) {
            log::warn!("Invalid value ({perf_pages}) for perf_pages, which must be a power of 2.");
            log::warn!("The default value {PERF_PAGES_DEFAULT} will be used.");
            perf_pages = PERF_PAGES_DEFAULT;
        }
        // aya doesn't support specifying from userspace wether or not to pin maps.
        // As a hack we always pin and delete the folder on shutdown.
        let pinning_path = match pinning {
            Pinning::Enabled => PINNED_MAPS_PATH.to_string(),
            Pinning::Disabled => format!("{}_tmp", PINNED_MAPS_PATH),
        };

        Ok(Self {
            pinning,
            btf: Arc::new(btf),
            perf_pages,
            pinning_path,
            log_level,
        })
    }
}

#[derive(Error, Debug)]
pub enum ProgramError {
    #[error("loading probe")]
    LoadingProbe(#[from] aya::BpfError),
    #[error("program not found {0}")]
    ProgramNotFound(String),
    #[error(transparent)]
    ProgramError(#[from] aya::programs::ProgramError),
    #[error(transparent)]
    MapError(#[from] aya::maps::MapError),
    #[error("perf buffer error {0}")]
    PerfBuffer(#[from] PerfBufferError),
    #[error("loading BTF {0}")]
    BtfError(#[from] BtfError),
    #[error("running background aya task {0}")]
    JoinError(#[from] JoinError),
}

pub struct ProgramBuilder {
    /// probe name, used for logging purposes
    name: &'static str,
    /// Probe configuration
    ctx: BpfContext,
    probe: Vec<u8>,
    tracepoints: Vec<(String, String)>,
    raw_tracepoints: Vec<String>,
    kprobes: Vec<String>,
    kretprobes: Vec<String>,
    lsms: Vec<String>,
}

impl ProgramBuilder {
    pub fn new(ctx: BpfContext, name: &'static str, probe: Vec<u8>) -> Self {
        Self {
            ctx,
            name,
            probe,
            tracepoints: Vec::new(),
            raw_tracepoints: Vec::new(),
            kprobes: Vec::new(),
            kretprobes: Vec::new(),
            lsms: Vec::new(),
        }
    }

    pub fn tracepoint(mut self, section: &str, tracepoint: &str) -> Self {
        self.tracepoints
            .push((section.to_string(), tracepoint.to_string()));
        self
    }

    pub fn raw_tracepoint(mut self, raw_tracepoint: &str) -> Self {
        self.raw_tracepoints.push(raw_tracepoint.to_string());
        self
    }

    pub fn kprobe(mut self, name: &str) -> Self {
        self.kprobes.push(name.to_string());
        self
    }

    pub fn kretprobe(mut self, name: &str) -> Self {
        self.kretprobes.push(name.to_string());
        self
    }

    pub fn lsm(mut self, name: &str) -> Self {
        self.lsms.push(name.to_string());
        self
    }

    pub async fn start(self) -> Result<Program, ProgramError> {
        // We need to notify background tasks reading from maps that we're shutting down.
        // We must use oneshot::Receiver as the main shut down machanism because it has
        // blocking_recv. Background tasks need an async notification tought, and we can't
        // clone oneshots, so we're forced to make an extra channel.
        // It would have been perfect if dropping aya::Bpf would have caused an error on
        // background maps, but that's not the case: the map file descriptor is dropped
        // when all Map usage is dropped.
        let (tx_exit, _) = watch::channel(());
        let btf = self.ctx.btf.clone();
        let ctx = self.ctx.clone();
        let name = self.name.to_string();

        let bpf = tokio::task::spawn_blocking(move || {
            let _ = std::fs::create_dir(&self.ctx.pinning_path);
            let mut bpf = BpfLoader::new()
                .map_pin_path(&self.ctx.pinning_path)
                .btf(Some(btf.as_ref()))
                .set_global("log_level", &(self.ctx.log_level as i32))
                .load(&self.probe)?;
            for (section, tracepoint) in self.tracepoints {
                let tp: &mut TracePoint = bpf
                    .program_mut(&tracepoint)
                    .ok_or_else(|| ProgramError::ProgramNotFound(tracepoint.clone()))?
                    .try_into()?;
                tp.load()?;
                tp.attach(&section, &tracepoint)?;
            }
            for raw_tracepoint in self.raw_tracepoints {
                let tp: &mut RawTracePoint = bpf
                    .program_mut(&raw_tracepoint)
                    .ok_or_else(|| ProgramError::ProgramNotFound(raw_tracepoint.clone()))?
                    .try_into()?;
                tp.load()?;
                tp.attach(&raw_tracepoint)?;
            }
            for kprobe in self.kprobes {
                let tp: &mut KProbe = bpf
                    .program_mut(&kprobe)
                    .ok_or_else(|| ProgramError::ProgramNotFound(kprobe.clone()))?
                    .try_into()?;
                tp.load()?;
                tp.attach(&kprobe, 0)?;
            }
            for kretprobe in self.kretprobes {
                let program = format!("{kretprobe}_return");
                let tp: &mut KProbe = bpf
                    .program_mut(&program)
                    .ok_or_else(|| ProgramError::ProgramNotFound(program.clone()))?
                    .try_into()?;
                tp.load()?;
                tp.attach(&kretprobe, 0)?;
            }
            for lsm in self.lsms {
                let tp: &mut Lsm = bpf
                    .program_mut(&lsm)
                    .ok_or_else(|| ProgramError::ProgramNotFound(lsm.clone()))?
                    .try_into()?;
                tp.load(&lsm, &btf)?;
                tp.attach()?;
            }
            Result::<Bpf, ProgramError>::Ok(bpf)
        })
        .await
        .expect("join error")?;

        Ok(Program {
            tx_exit,
            name,
            ctx,
            bpf,
        })
    }
}

pub struct Program {
    /// Signal from the background thread to the background async tasks that
    /// we're exiting.
    tx_exit: watch::Sender<()>,
    ctx: BpfContext,
    name: String,
    bpf: Bpf,
}

impl Drop for Program {
    fn drop(&mut self) {
        if matches!(self.ctx.pinning, Pinning::Disabled) {
            let _ = std::fs::remove_dir_all(&self.ctx.pinning_path);
        }
    }
}

impl Program {
    pub fn bpf(&mut self) -> &mut Bpf {
        &mut self.bpf
    }
    /// Poll a BPF_MAP_TYPE_HASH with a certain interval
    pub async fn poll<F, K, V>(
        &self,
        map_name: &str,
        interval: Duration,
        mut poll_fn: F,
    ) -> Result<(), ProgramError>
    where
        F: FnMut(Result<&mut HashMap<MapRefMut, K, V>, ProgramError>),
        F: Send + 'static,
        K: Pod + 'static + Send,
        V: Pod + 'static + Send,
    {
        let mut map: HashMap<_, K, V> = self.bpf.map_mut(map_name)?.try_into()?;
        let mut rx_exit = self.tx_exit.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    Err(_) = rx_exit.changed() => break,
                    _ = interval.tick() => poll_fn(Ok(&mut map)),
                };
            }
        });
        Ok(())
    }

    /// Watch a BPF_MAP_TYPE_PERF_EVENT_ARRAY and forward all its events to `sender`.
    /// A different task is run for each CPU.
    pub async fn read_events<T: Send>(
        &self,
        map_name: &str,
        sender: impl BpfSender<T>,
    ) -> Result<(), ProgramError> {
        let mut perf_array: AsyncPerfEventArray<_> = self.bpf.map_mut(map_name)?.try_into()?;
        let maps = online_cpus()
            .unwrap()
            .into_iter()
            .map(|cpu_id| {
                perf_array
                    .open(cpu_id, Some(self.ctx.perf_pages))
                    .map_err(ProgramError::from)
            })
            .collect::<Result<Vec<_>, ProgramError>>()?;
        for mut buf in maps {
            let name = self.name.clone();
            let mut sender = sender.clone();
            let mut rx_exit = self.tx_exit.subscribe();
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(size_of::<BpfEvent<T>>() + PERF_HEADER_SIZE))
                    .collect::<Vec<_>>();
                loop {
                    let events = tokio::select! {
                        Err(_) = rx_exit.changed() => return,
                        events = buf.read_events(&mut buffers) => events,
                    };
                    match events {
                        Ok(events) => {
                            if events.lost > 0 {
                                log::warn!(
                                    "{}: Lost {} events (read {})",
                                    name,
                                    events.lost,
                                    events.read
                                );
                            }
                            for buf in buffers.iter_mut().take(events.read) {
                                let ptr = buf.as_ptr() as *const BpfEvent<T>;
                                let event = unsafe { ptr.read_unaligned() };
                                sender.send(Ok(event))
                            }
                        }
                        Err(e) => return sender.send(Err(e.into())),
                    };
                }
            });
        }
        Ok(())
    }
}

#[cfg(feature = "test-utils")]
pub fn load_test_program(probe: &[u8]) -> Result<Bpf, ProgramError> {
    let _ = std::fs::create_dir(PINNED_MAPS_PATH);
    let bpf = BpfLoader::new()
        .map_pin_path(PINNED_MAPS_PATH)
        .load(probe)?;
    Ok(bpf)
}

#[derive(Debug)]
#[repr(C)]
pub struct BpfEvent<P> {
    pub timestamp: Timestamp,
    pub pid: Pid,
    pub payload: P,
}

impl<P: fmt::Display> fmt::Display for BpfEvent<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.timestamp, self.pid, self.payload)
    }
}
