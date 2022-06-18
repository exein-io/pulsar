//! [`Program`] is a wrapper around [`aya::Bpf`] which:
//! - runs background thread which sets up the probe and waits for a shutdown signal
//! - allows to to read events events.
//!
use core::fmt;
use std::{mem::size_of, sync::Arc, time::Duration};

use aya::{
    maps::{
        perf::{AsyncPerfEventArray, PerfBufferError},
        HashMap, MapRefMut,
    },
    util::online_cpus,
    Bpf, BpfLoader, Btf, BtfError,
};
use bytes::BytesMut;
use thiserror::Error;
use tokio::sync::{oneshot, watch};

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
    /// Btf allows to load it only once on startup
    btf: Arc<Btf>,
    /// How many pages of memory (4Kb) to use for perf arrays.
    /// NOTE: this will result in a memory usage of:
    /// (number of modules) * (number of cores) * (perf_pages) * 4Kb
    perf_pages: usize,
}

#[derive(Clone)]
pub enum Pinning {
    Enabled,
    Disabled,
}

impl BpfContext {
    pub fn new(pinning: Pinning, mut perf_pages: usize) -> Result<Self, ProgramError> {
        let btf = Btf::from_sys_fs()?;
        if perf_pages == 0 || (perf_pages & (perf_pages - 1) != 0) {
            log::warn!("Invalid value ({perf_pages}) for perf_pages, which must be a power of 2.");
            log::warn!("The default value {PERF_PAGES_DEFAULT} will be used.");
            perf_pages = PERF_PAGES_DEFAULT;
        }
        Ok(Self {
            pinning,
            btf: Arc::new(btf),
            perf_pages,
        })
    }
}

pub struct Program<T> {
    /// The background thread signals here that Bpf has been loaded
    rx_ready: oneshot::Receiver<Result<T, ProgramError>>,
    /// Signal to the background thread that the program has been dropped and
    /// we should cleanup all Bpf.
    tx_shutdown: oneshot::Sender<()>,
    /// Signal from the background thread to the background async tasks that
    /// we're exiting.
    rx_exit: watch::Receiver<()>,
    /// probe name, used for logging purposes
    name: &'static str,
    /// Probe configuration
    ctx: BpfContext,
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
}

pub struct ProgramHandle {
    pub(crate) _tx_shutdown: oneshot::Sender<()>,
    pub(crate) rx_full_inizialized: Option<oneshot::Receiver<()>>,
}

impl ProgramHandle {
    /// Wait for the full initialization of the map consumer. For perf event arrays,
    /// this is the moment the map is opened on a given CPU. Waiting for this event
    /// allows tests to know when it's safe to run the trigger programs.
    pub async fn fully_initialized(&mut self) {
        match self.rx_full_inizialized.take() {
            Some(rx_full_inizialized) => {
                let _ = rx_full_inizialized.await;
            }
            None => {}
        }
    }
}

impl<T: 'static + Send> Program<T> {
    // TODO: aya::Bpf is Send since 0.11, so this code can be simplified.
    /// Since [`aya::Bpf`] is  non-[`std::marker::Send`], it must reside on a single thread.
    /// First the program is loaded from the `probe` binary, than the setup function
    /// `setup_fn` is run.
    ///
    /// The result of the provided function is provided to an inner channel and it signals
    /// the BPF program is ready to be used. If there's an error loading the probe or during
    /// the setup function, it is propagated over inner channel.
    ///
    /// When we receive the shutdown signal, we cleanup resourced by dropping Bpf and signaling
    /// background tasks to exit.
    pub fn start<F>(ctx: BpfContext, name: &'static str, probe: Vec<u8>, setup_fn: F) -> Self
    where
        F: FnOnce(&mut Bpf) -> Result<T, ProgramError>,
        F: 'static + Send,
    {
        let (tx_shutdown, rx_shutdown) = oneshot::channel();
        let (tx_ready, rx_ready) = oneshot::channel::<Result<T, ProgramError>>();
        // We need to notify background tasks reading from maps that we're shutting down.
        // We must use oneshot::Receiver as the main shut down machanism because it has
        // blocking_recv. Background tasks need an async notification tought, and we can't
        // clone oneshots, so we're forced to make an extra channel.
        // It would have been perfect if dropping aya::Bpf would have caused an error on
        // background maps, but that's not the case: the map file descriptor is dropped
        // when all Map usage is dropped.
        let (tx_exit, rx_exit) = watch::channel(());
        let pinning = ctx.pinning.clone();
        let btf = ctx.btf.clone();
        std::thread::spawn(move || {
            // aya doesn't support specifying from userspace wether or not to pin maps.
            // As a hack we always pin and delete the folder on shutdown.
            let pinning_path = match pinning {
                Pinning::Enabled => PINNED_MAPS_PATH.to_string(),
                Pinning::Disabled => format!("{}_tmp", PINNED_MAPS_PATH),
            };
            let _ = std::fs::create_dir(&pinning_path);
            match BpfLoader::new()
                .map_pin_path(&pinning_path)
                .btf(Some(btf.as_ref()))
                .load(&probe)
            {
                Err(e) => {
                    let _ = tx_ready.send(Err(e.into()));
                }
                Ok(mut bpf) => {
                    let result = setup_fn(&mut bpf);
                    let _ = tx_ready.send(result);
                    let _ = rx_shutdown.blocking_recv();
                    drop(tx_exit);
                    if matches!(pinning, Pinning::Disabled) {
                        let _ = std::fs::remove_dir_all(&pinning_path);
                    }
                }
            }
        });
        Self {
            rx_ready,
            rx_exit,
            tx_shutdown,
            name,
            ctx,
        }
    }
}

impl<K: 'static + Send, V: 'static + Send> Program<HashMap<MapRefMut, K, V>> {
    /// Poll a BPF_MAP_TYPE_HASH with a certain interval
    pub fn poll<F>(self, interval: Duration, mut poll_fn: F) -> ProgramHandle
    where
        F: FnMut(Result<&mut HashMap<MapRefMut, K, V>, ProgramError>),
        F: Send + 'static,
    {
        let Self {
            rx_ready,
            mut rx_exit,
            tx_shutdown,
            ..
        } = self;
        let (tx_full_inizialized, rx_full_inizialized) = oneshot::channel();
        tokio::spawn(async move {
            let mut monitored_map = match rx_ready.await.expect("thread failed") {
                Ok(monitored_map) => monitored_map,
                Err(e) => return poll_fn(Err(e)),
            };
            let _ = tx_full_inizialized.send(());
            let mut interval = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    Err(_) = rx_exit.changed() => break,
                    _ = interval.tick() => poll_fn(Ok(&mut monitored_map)),
                };
            }
        });
        ProgramHandle {
            _tx_shutdown: tx_shutdown,
            rx_full_inizialized: Some(rx_full_inizialized),
        }
    }
}

impl Program<AsyncPerfEventArray<MapRefMut>> {
    /// Watch a BPF_MAP_TYPE_PERF_EVENT_ARRAY and forward all its events to `sender`.
    /// A different task is run for each CPU.
    pub fn read_events<T: Send>(self, sender: impl BpfSender<T>) -> ProgramHandle {
        let Self {
            rx_ready,
            rx_exit,
            tx_shutdown,
            name,
            ctx,
        } = self;
        let (tx_full_inizialized, rx_full_inizialized) = oneshot::channel();
        tokio::spawn(async move {
            consume_perf_buffer(rx_ready, tx_full_inizialized, sender, rx_exit, name, ctx).await
        });
        ProgramHandle {
            _tx_shutdown: tx_shutdown,
            rx_full_inizialized: Some(rx_full_inizialized),
        }
    }
}

async fn consume_perf_buffer<T: Send>(
    rx_ready: oneshot::Receiver<Result<AsyncPerfEventArray<MapRefMut>, ProgramError>>,
    tx_full_inizialized: oneshot::Sender<()>,
    mut sender: impl BpfSender<T>,
    rx_exit: watch::Receiver<()>,
    name: &'static str,
    ctx: BpfContext,
) {
    let mut perf_array = match rx_ready.await.expect("thread failed") {
        Ok(perf_array) => perf_array,
        Err(e) => return sender.send(Err(e)),
    };
    let maps = online_cpus()
        .unwrap()
        .into_iter()
        .map(|cpu_id| perf_array.open(cpu_id, Some(ctx.perf_pages)))
        .collect::<Result<Vec<_>, _>>();
    let maps = match maps {
        Ok(maps) => maps,
        Err(e) => return sender.send(Err(e.into())),
    };
    let _ = tx_full_inizialized.send(());
    for mut buf in maps {
        let mut sender = sender.clone();
        let mut rx_exit = rx_exit.clone();
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
}

#[cfg(feature = "test-utils")]
pub fn load_test_program(probe: Vec<u8>) -> Result<Bpf, ProgramError> {
    let _ = std::fs::create_dir(PINNED_MAPS_PATH);
    let bpf = BpfLoader::new()
        .map_pin_path(PINNED_MAPS_PATH)
        .load(&probe)?;
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
