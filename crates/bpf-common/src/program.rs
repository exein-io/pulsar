//! [`Program`] is a wrapper around [`aya::Bpf`] which:
//! - runs background thread which sets up the probe and waits for a shutdown signal
//! - allows to read events events.
//!
use core::fmt;
use std::{
    collections::HashSet, convert::TryFrom, fmt::Display, mem::size_of, sync::Arc, time::Duration,
};

use aya::{
    maps::{
        perf::{AsyncPerfEventArray, PerfBufferError},
        Array, HashMap, Map, MapData,
    },
    programs::{KProbe, Lsm, RawTracePoint, TracePoint},
    util::online_cpus,
    Bpf, BpfLoader, Btf, BtfError, Pod,
};
use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;
use tokio::{sync::watch, task::JoinError};

use crate::{feature_autodetect::kernel_version::KernelVersion, time::Timestamp, BpfSender, Pid};

const PERF_HEADER_SIZE: usize = 4;
const PINNED_MAPS_PATH: &str = "/sys/fs/bpf/pulsar";

pub const PERF_PAGES_DEFAULT: usize = 4096;

/// Max buffer size in bytes
const BUFFER_MAX: usize = 16384;

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
    /// Kernel version
    kernel_version: KernelVersion,
    /// LSM support
    lsm_supported: bool,
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
        lsm_supported: bool,
    ) -> Result<Self, ProgramError> {
        let btf = Btf::from_sys_fs()?;
        if perf_pages == 0 || (perf_pages & (perf_pages - 1) != 0) {
            log::warn!("Invalid value ({perf_pages}) for perf_pages, which must be a power of 2.");
            log::warn!("The default value {PERF_PAGES_DEFAULT} will be used.");
            perf_pages = PERF_PAGES_DEFAULT;
        }
        let kernel_version = match KernelVersion::autodetect() {
            Ok(version) => version,
            Err(err) => {
                log::warn!("Error identifying kernel version {err:?}. Assuming kernel 5.0.4");
                KernelVersion {
                    major: 5,
                    minor: 0,
                    patch: 4,
                }
            }
        };
        // aya doesn't support specifying from userspace wether or not to pin maps.
        // As a hack we always pin and delete the folder on shutdown.
        let pinning_path = match pinning {
            Pinning::Enabled => PINNED_MAPS_PATH.to_string(),
            Pinning::Disabled => format!("{PINNED_MAPS_PATH}_tmp"),
        };

        Ok(Self {
            pinning,
            btf: Arc::new(btf),
            perf_pages,
            pinning_path,
            log_level,
            kernel_version,
            lsm_supported,
        })
    }

    pub fn lsm_supported(&self) -> bool {
        self.lsm_supported
    }

    pub fn kernel_version(&self) -> &KernelVersion {
        &self.kernel_version
    }
}

/// Return the correct version of the eBPF binary to load.
/// On kernel >= 5.13.0 we'll load 'probe_full.bpf.o'
/// On kernel < 5.13.0 we'll load 'probe_no_fn_ptr.bpf.o'
/// Note: Both programs are embedded in the pulsar binary. The choice is made
/// at runtime.
#[macro_export]
macro_rules! ebpf_program {
    ( $ctx: expr , $probe: expr) => {{
        use bpf_common::aya::include_bytes_aligned;
        use bpf_common::feature_autodetect::kernel_version::KernelVersion;

        let full =
            include_bytes_aligned!(concat!(env!("OUT_DIR"), "/", $probe, ".full.bpf.o")).into();
        let no_loop =
            include_bytes_aligned!(concat!(env!("OUT_DIR"), "/", $probe, ".no_fn_ptr.bpf.o"))
                .into();
        if $ctx.kernel_version().as_i32()
            >= (KernelVersion {
                major: 5,
                minor: 13,
                patch: 0,
            })
            .as_i32()
        {
            full
        } else {
            no_loop
        }
    }};
}

#[derive(Error, Debug)]
pub enum ProgramError {
    #[error("loading probe")]
    LoadingProbe(#[from] aya::BpfError),
    #[error("program not found {0}")]
    ProgramNotFound(String),
    #[error("incorrect program type {0}")]
    ProgramTypeError(String),
    #[error("failed program load {program}")]
    ProgramLoadError {
        program: String,
        #[source]
        program_error: Box<aya::programs::ProgramError>,
    },
    #[error("failed program attach {program}")]
    ProgramAttachError {
        program: String,
        #[source]
        program_error: Box<aya::programs::ProgramError>,
    },
    #[error(transparent)]
    MapError(#[from] aya::maps::MapError),
    #[error("map not found {0}")]
    MapNotFound(String),
    #[error("map already used {0}")]
    MapAlreadyUsed(String),
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
    programs: Vec<ProgramType>,
}

impl ProgramBuilder {
    pub fn new(ctx: BpfContext, name: &'static str, probe: Vec<u8>) -> Self {
        Self {
            ctx,
            name,
            probe,
            programs: Vec::new(),
        }
    }

    pub fn tracepoint(mut self, section: &str, tracepoint: &str) -> Self {
        self.programs.push(ProgramType::TracePoint(
            section.to_string(),
            tracepoint.to_string(),
        ));
        self
    }

    pub fn raw_tracepoint(mut self, name: &str) -> Self {
        self.programs
            .push(ProgramType::RawTracePoint(name.to_string()));
        self
    }

    pub fn kprobe(mut self, name: &str) -> Self {
        self.programs.push(ProgramType::Kprobe(name.to_string()));
        self
    }

    pub fn kretprobe(mut self, name: &str) -> Self {
        self.programs.push(ProgramType::Kretprobe(name.to_string()));
        self
    }

    pub fn lsm(mut self, name: &str) -> Self {
        self.programs.push(ProgramType::Lsm(name.to_string()));
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
                .set_global("LINUX_KERNEL_VERSION", &self.ctx.kernel_version.as_i32())
                .load(&self.probe)?;
            for program in self.programs {
                program.attach(&mut bpf, &btf)?;
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
            used_maps: Default::default(),
        })
    }
}

enum ProgramType {
    TracePoint(String, String),
    RawTracePoint(String),
    Kprobe(String),
    Kretprobe(String),
    Lsm(String),
}

impl Display for ProgramType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProgramType::TracePoint(section, tracepoint) => {
                write!(f, "tracepoint {section}/{tracepoint}")
            }
            ProgramType::RawTracePoint(tracepoint) => write!(f, "raw_tracepoint {tracepoint}"),
            ProgramType::Kprobe(kprobe) => write!(f, "kprobe {kprobe}"),
            ProgramType::Kretprobe(kretprobe) => write!(f, "kretprobe {kretprobe}"),
            ProgramType::Lsm(lsm) => write!(f, "lsm {lsm}"),
        }
    }
}

impl ProgramType {
    fn attach(&self, bpf: &mut Bpf, btf: &Btf) -> Result<(), ProgramError> {
        let load_err = |program_error| ProgramError::ProgramLoadError {
            program: self.to_string(),
            program_error: Box::new(program_error),
        };
        let attach_err = |program_error| ProgramError::ProgramAttachError {
            program: self.to_string(),
            program_error: Box::new(program_error),
        };
        match self {
            ProgramType::TracePoint(section, tracepoint) => {
                let program: &mut TracePoint = extract_program(bpf, tracepoint)?;
                program.load().map_err(load_err)?;
                program.attach(section, tracepoint).map_err(attach_err)?;
            }
            ProgramType::RawTracePoint(tracepoint) => {
                let program: &mut RawTracePoint = extract_program(bpf, tracepoint)?;
                program.load().map_err(load_err)?;
                program.attach(tracepoint).map_err(attach_err)?;
            }
            ProgramType::Kretprobe(kprobe) | ProgramType::Kprobe(kprobe) => {
                let program: &mut KProbe = extract_program(bpf, kprobe)?;
                program.load().map_err(load_err)?;
                program.attach(kprobe, 0).map_err(attach_err)?;
            }
            ProgramType::Lsm(lsm) => {
                let program: &mut Lsm = extract_program(bpf, lsm)?;
                program.load(lsm, btf).map_err(load_err)?;
                program.attach().map_err(attach_err)?;
            }
        }
        Ok(())
    }
}

fn extract_program<'a, T>(bpf: &'a mut Bpf, program: &str) -> Result<&'a mut T, ProgramError>
where
    T: 'a,
    &'a mut T: TryFrom<&'a mut aya::programs::Program>,
{
    bpf.program_mut(program)
        .ok_or_else(|| ProgramError::ProgramNotFound(program.to_string()))?
        .try_into()
        .map_err(|_err| ProgramError::ProgramTypeError(program.to_string()))
}

pub struct Program {
    /// Signal from the background thread to the background async tasks that
    /// we're exiting.
    tx_exit: watch::Sender<()>,
    ctx: BpfContext,
    name: String,
    bpf: Bpf,
    used_maps: HashSet<String>,
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
        &mut self,
        map_name: &str,
        interval: Duration,
        mut poll_fn: F,
    ) -> Result<(), ProgramError>
    where
        F: FnMut(&mut HashMap<MapData, K, V>),
        F: Send + 'static,
        K: Pod + 'static + Send,
        V: Pod + 'static + Send,
    {
        let map_resource = self.take_map(map_name)?;

        let mut rx_exit = self.tx_exit.subscribe();
        let mut map = HashMap::try_from(map_resource)?;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    Err(_) = rx_exit.changed() => break,
                    _ = interval.tick() => poll_fn(&mut map),
                };
            }
        });
        Ok(())
    }

    /// Watch a BPF_MAP_TYPE_PERF_EVENT_ARRAY and forward all its events to `sender`.
    /// A different task is run for each CPU.
    pub async fn read_events<T: Send>(
        &mut self,
        map_name: &str,
        sender: impl BpfSender<T>,
    ) -> Result<(), ProgramError> {
        let map_resource = self.take_map(map_name)?;

        let mut perf_array: AsyncPerfEventArray<_> = AsyncPerfEventArray::try_from(map_resource)?;
        let mut init_map = Array::try_from(
            self.bpf
                .take_map("init_map")
                .ok_or_else(|| ProgramError::MapNotFound("init_map".to_string()))?,
        )?;

        let buffers = online_cpus()
            .unwrap()
            .into_iter()
            .map(|cpu_id| perf_array.open(cpu_id, Some(self.ctx.perf_pages)))
            .collect::<Result<Vec<_>, PerfBufferError>>()?;
        for mut buf in buffers {
            let name = self.name.clone();
            let mut sender = sender.clone();
            let mut rx_exit = self.tx_exit.subscribe();
            let event_size: usize = size_of::<RawBpfEvent<T>>();
            let buffer_size: usize = event_size + PERF_HEADER_SIZE + BUFFER_MAX;
            tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(buffer_size))
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
                            for buffer in buffers.iter_mut().take(events.read) {
                                if buffer.len() < event_size {
                                    log::error!("sizeof T: {}", size_of::<T>());
                                    log::error!(
                                        "sizeof RawBpfEvent<T>: {}",
                                        size_of::<RawBpfEvent<T>>()
                                    );
                                    panic!("Buffer too short. buffer.len() = {}", buffer.len(),);
                                }
                                let mut buffer =
                                    std::mem::replace(buffer, BytesMut::with_capacity(buffer_size));
                                let ptr = buffer.as_ptr() as *const RawBpfEvent<T>;
                                let raw = unsafe { ptr.read_unaligned() };
                                buffer.advance(event_size);
                                // NOTE: read buffer will be padded. Eg. if the eBPF program
                                // writes 3 bytes, we'll read 4, with the forth being a 0.
                                // This is why we need buffer_len and can't rely on the
                                // received buffer alone.
                                buffer.truncate(raw.buffer.buffer_len as usize);
                                let buffer = buffer.freeze();
                                sender.send(Ok(BpfEvent {
                                    timestamp: raw.timestamp,
                                    pid: raw.pid,
                                    payload: raw.payload,
                                    buffer,
                                }))
                            }
                        }
                        Err(e) => return sender.send(Err(e.into())),
                    };
                }
            });
        }

        // Signal eBPF program we're ready by setting STATUS_INITIALIZED
        if let Err(err) = init_map.set(0, 1_u32, 0) {
            log::warn!(
                "Error setting STATUS_INITIALIZED for {}: {:?}",
                self.name,
                err
            );
        };
        Ok(())
    }

    fn take_map(&mut self, map_name: &str) -> Result<Map, ProgramError> {
        if self.used_maps.contains(map_name) {
            return Err(ProgramError::MapAlreadyUsed(map_name.to_string()));
        };

        let map_resource = self
            .bpf
            .take_map(map_name)
            .ok_or_else(|| ProgramError::MapNotFound(map_name.to_string()))?;

        self.used_maps.insert(map_name.to_string());
        Ok(map_resource)
    }
}

#[derive(Debug)]
pub struct BpfEvent<P> {
    pub timestamp: Timestamp,
    pub pid: Pid,
    pub payload: P,
    pub buffer: Bytes,
}

#[repr(C)]
pub struct RawBpfEvent<P> {
    timestamp: Timestamp,
    pid: Pid,
    payload: P,
    buffer: Buffer,
}

#[repr(C, align(8))]
struct Buffer {
    pub buffer_len: u32,
}

impl<P: fmt::Display> fmt::Display for BpfEvent<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.timestamp, self.pid, self.payload)
    }
}
