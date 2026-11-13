//! Loading probe objects so that they all write into one ring.
//!
//! Every object is loaded with the same pin directory and ring size: the
//! first one creates and pins `pulsar_events` and `pulsar_lost`, every later
//! one, extensions included, reuses them by name.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use aya::{
    Btf, Ebpf, EbpfError, EbpfLoader,
    programs::{KProbe, Lsm, RawTracePoint},
    util::{KernelVersion, online_cpus},
};
use bpf_feature_autodetect::autodetect_features;
use bpf_features::BpfFeatures;
use nix::sys::resource::{Resource, setrlimit};
use thiserror::Error;

use crate::{
    ProducerId,
    abi::{PULSAR_ABI_VERSION, PULSAR_PRODUCER_MAX},
    objects,
    ring::RING_MAP,
};

pub const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/pulsar-next/v1";

/// What [`Loader`] needs to load and attach a probe.
pub struct ProbeSpec {
    pub name: &'static str,
    /// One object per set of kernel features (see `next_bpf_builder::embed`).
    pub objects: &'static [(BpfFeatures, &'static [u8])],
    /// The programs to attach on a kernel with the given features.
    pub programs: fn(&BpfFeatures) -> Vec<Attach>,
}

/// A program of the object and where to attach it.
#[derive(Clone, Copy, Debug)]
pub enum Attach {
    /// Program named like the tracepoint.
    RawTracePoint(&'static str),
    /// Program named like the kernel function.
    Kprobe(&'static str),
    /// Program named like the LSM hook.
    Lsm(&'static str),
}

impl Attach {
    fn program(&self) -> &'static str {
        match self {
            Attach::RawTracePoint(name) | Attach::Kprobe(name) | Attach::Lsm(name) => name,
        }
    }
}

/// The `log_level` of the probes (`LOG_LEVEL_*` in common.bpf.h).
#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Disabled = 0,
    Error = 1,
    Debug = 2,
}

#[derive(Clone, Debug)]
pub struct LoaderConfig {
    pub pin_dir: PathBuf,
    /// Size of the shared ring in bytes: a power of two and a multiple of the
    /// page size.
    pub ring_size: u32,
    pub log_level: LogLevel,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            pin_dir: PathBuf::from(DEFAULT_PIN_DIR),
            ring_size: default_ring_size(),
            log_level: LogLevel::Error,
        }
    }
}

/// 2 MiB per CPU, rounded up to a power of two, between 8 and 128 MiB.
pub fn default_ring_size() -> u32 {
    const MIB: usize = 1024 * 1024;
    let cpus = online_cpus().map_or(1, |cpus| cpus.len());
    let size = (2 * MIB * cpus)
        .next_power_of_two()
        .clamp(8 * MIB, 128 * MIB);
    size as u32
}

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("raising the memlock limit")]
    Memlock(#[source] nix::Error),
    #[error("ring size {0} is not a power of two multiple of the page size")]
    RingSize(u32),
    #[error("preparing the pin directory {path}")]
    PinDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("reading the kernel BTF")]
    Btf(#[from] aya::BtfError),
    #[error("reading the kernel version: {0}")]
    KernelVersion(String),
    #[error("{probe}: no object built for {features:?}")]
    NoVariant {
        probe: &'static str,
        features: BpfFeatures,
    },
    #[error("{probe}: all {PULSAR_PRODUCER_MAX} producer ids are taken")]
    TooManyProducers { probe: &'static str },
    #[error("{probe}: object not built against ABI version {PULSAR_ABI_VERSION}")]
    AbiMismatch { probe: &'static str },
    #[error("{probe}: loading the object")]
    Load {
        probe: &'static str,
        #[source]
        source: Box<EbpfError>,
    },
    #[error("{probe}: program {program} not found")]
    ProgramNotFound {
        probe: &'static str,
        program: &'static str,
    },
    #[error("{probe}: attaching {attach:?}")]
    Attach {
        probe: &'static str,
        attach: Attach,
        #[source]
        source: Box<aya::programs::ProgramError>,
    },
}

/// Loads probe objects into the shared ring, giving each its producer id.
pub struct Loader {
    config: LoaderConfig,
    features: BpfFeatures,
    btf: Btf,
    kernel_version: u32,
    next_producer: u32,
}

impl Loader {
    /// Removes the pins of an earlier run: they would be reused as they are.
    pub fn new(config: LoaderConfig) -> Result<Self, LoadError> {
        let page_size = nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
            .ok()
            .flatten()
            .unwrap_or(4096) as u32;
        if !config.ring_size.is_power_of_two() || !config.ring_size.is_multiple_of(page_size) {
            return Err(LoadError::RingSize(config.ring_size));
        }
        // Map memory is charged to RLIMIT_MEMLOCK before kernel 5.11.
        setrlimit(Resource::RLIMIT_MEMLOCK, u64::MAX, u64::MAX).map_err(LoadError::Memlock)?;
        reset_pin_dir(&config.pin_dir).map_err(|source| LoadError::PinDir {
            path: config.pin_dir.clone(),
            source,
        })?;
        let kernel_version = KernelVersion::current()
            .map_err(|err| LoadError::KernelVersion(err.to_string()))?
            .code();
        Ok(Self {
            features: autodetect_features(),
            btf: Btf::from_sys_fs()?,
            kernel_version,
            // 0 is never assigned, so an object loaded some other way stands out.
            next_producer: 1,
            config,
        })
    }

    pub fn features(&self) -> &BpfFeatures {
        &self.features
    }

    pub fn pin_dir(&self) -> &Path {
        &self.config.pin_dir
    }

    /// Loads the object of `spec` built for this kernel, under a new producer
    /// id. Nothing is attached yet.
    pub fn load(&mut self, spec: &ProbeSpec) -> Result<LoadedProbe, LoadError> {
        let probe = spec.name;
        let object =
            objects::select(spec.objects, &self.features).ok_or_else(|| LoadError::NoVariant {
                probe,
                features: self.features.clone(),
            })?;
        let producer = self.next_producer;
        if producer >= PULSAR_PRODUCER_MAX {
            return Err(LoadError::TooManyProducers { probe });
        }
        // The value doesn't matter: only an object built against this ABI
        // version has a global with this name (see ring.bpf.h).
        let stamp = format!("PULSAR_ABI_V{PULSAR_ABI_VERSION}");
        let ebpf = EbpfLoader::new()
            .btf(Some(&self.btf))
            .default_map_pin_directory(&self.config.pin_dir)
            .map_max_entries(RING_MAP, self.config.ring_size)
            .override_global(&stamp, &0u32, true)
            .override_global("PULSAR_PRODUCER_ID", &producer, true)
            .override_global("log_level", &(self.config.log_level as i32), true)
            .override_global("LINUX_KERNEL_VERSION", &self.kernel_version, true)
            .load(object)
            .map_err(|source| match source {
                EbpfError::ParseError(aya_obj::ParseError::SymbolNotFound { ref name })
                    if *name == stamp =>
                {
                    LoadError::AbiMismatch { probe }
                }
                source => LoadError::Load {
                    probe,
                    source: Box::new(source),
                },
            })?;
        self.next_producer += 1;
        Ok(LoadedProbe {
            name: probe,
            producer: ProducerId(producer),
            programs: (spec.programs)(&self.features),
            ebpf,
        })
    }

    /// Loads and attaches every program of `probe`.
    pub fn attach(&self, probe: &mut LoadedProbe) -> Result<(), LoadError> {
        for &attach in &probe.programs {
            let name = probe.name;
            let not_found = || LoadError::ProgramNotFound {
                probe: name,
                program: attach.program(),
            };
            let failed = |source| LoadError::Attach {
                probe: name,
                attach,
                source: Box::new(source),
            };
            let program = probe
                .ebpf
                .program_mut(attach.program())
                .ok_or_else(not_found)?;
            match attach {
                Attach::RawTracePoint(tracepoint) => {
                    let program: &mut RawTracePoint = program.try_into().map_err(failed)?;
                    program.load().map_err(failed)?;
                    program.attach(tracepoint).map_err(failed)?;
                }
                Attach::Kprobe(function) => {
                    let program: &mut KProbe = program.try_into().map_err(failed)?;
                    program.load().map_err(failed)?;
                    program.attach(function, 0).map_err(failed)?;
                }
                Attach::Lsm(hook) => {
                    let program: &mut Lsm = program.try_into().map_err(failed)?;
                    program.load(hook, &self.btf).map_err(failed)?;
                    program.attach().map_err(failed)?;
                }
            }
        }
        Ok(())
    }

    /// Removes the pins. Maps stay alive while something still uses them.
    pub fn remove_pins(&self) -> io::Result<()> {
        reset_pin_dir(&self.config.pin_dir)?;
        fs::remove_dir(&self.config.pin_dir)
    }
}

/// Creates `dir` and removes the pins in it. Only files directly in `dir` are
/// removed, so a wrong path can't take a whole tree with it.
fn reset_pin_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// A loaded object. Dropping it detaches its programs.
pub struct LoadedProbe {
    name: &'static str,
    producer: ProducerId,
    programs: Vec<Attach>,
    ebpf: Ebpf,
}

impl LoadedProbe {
    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn producer(&self) -> ProducerId {
        self.producer
    }

    /// For the maps a probe is configured through.
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }
}
