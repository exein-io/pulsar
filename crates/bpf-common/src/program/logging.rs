//! Forwarding of eBPF log records, written with the `AYA_LOG_*` macros, to the
//! [`log`] crate.

use aya::Ebpf;
use aya_log::EbpfLogger;
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::watch,
};

/// Maps a [`log::LevelFilter`] to the most verbose eBPF level, `None` disables
/// eBPF logging.
pub(super) fn ebpf_level(level: log::LevelFilter) -> Option<aya_log::Level> {
    match level {
        log::LevelFilter::Off => None,
        log::LevelFilter::Error => Some(aya_log::Level::Error),
        log::LevelFilter::Warn => Some(aya_log::Level::Warn),
        log::LevelFilter::Info => Some(aya_log::Level::Info),
        log::LevelFilter::Debug => Some(aya_log::Level::Debug),
        log::LevelFilter::Trace => Some(aya_log::Level::Trace),
    }
}

/// Forwards log records decoded by aya-log to the global logger.
///
/// The eBPF side leaves the target empty. Records are logged with the target
/// `<crate_name>::ebpf` of the module, so they can be filtered together with
/// the module's own logs, and with the source file and line as a message
/// prefix.
pub(super) struct ModuleLogger {
    target: String,
}

impl ModuleLogger {
    fn new(module_name: &str) -> Self {
        Self {
            target: format!("{}::ebpf", module_name.replace('-', "_")),
        }
    }
}

impl log::Log for ModuleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        log::logger().enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        let file = record.file().unwrap_or_default();
        let line = record.line().unwrap_or_default();
        log::logger().log(
            &log::Record::builder()
                .args(format_args!("[{file}:{line}] {}", record.args()))
                .target(&self.target)
                .level(record.level())
                .file(record.file())
                .line(record.line())
                .build(),
        );
    }

    fn flush(&self) {
        log::logger().flush()
    }
}

pub(super) fn init(bpf: &mut Ebpf, module_name: &str) -> Option<EbpfLogger<ModuleLogger>> {
    match EbpfLogger::init_with_logger(bpf, ModuleLogger::new(module_name)) {
        Ok(logger) => Some(logger),
        Err(aya_log::Error::MapNotFound) => {
            log::warn!("{module_name}: eBPF program has no log map");
            None
        }
        Err(err) => {
            log::warn!("{module_name}: eBPF logs are not available: {err}");
            None
        }
    }
}

/// Spawns a task which forwards eBPF log records until the program exits.
pub(super) fn spawn_reader(
    logger: EbpfLogger<ModuleLogger>,
    module_name: String,
    mut rx_exit: watch::Receiver<()>,
) {
    let mut logger = match AsyncFd::with_interest(logger, Interest::READABLE) {
        Ok(logger) => logger,
        Err(err) => {
            log::warn!("{module_name}: eBPF logs are not available: {err}");
            return;
        }
    };
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;

                Err(_) = rx_exit.changed() => {
                    flush(logger.get_mut(), &module_name);
                    return;
                }
                guard = logger.readable_mut() => match guard {
                    Ok(mut guard) => {
                        flush(guard.get_inner_mut(), &module_name);
                        guard.clear_ready();
                    }
                    Err(err) => {
                        log::warn!("{module_name}: stopped reading eBPF logs: {err}");
                        return;
                    }
                },
            }
        }
    });
}

fn flush(logger: &mut EbpfLogger<ModuleLogger>, module_name: &str) {
    // NOTE: aya-log 0.3 `EbpfLogger::flush` unwraps the result of decoding each
    // record, so a malformed record panics. Unwinding drops the ring buffer
    // item, which consumes the record, so catching the panic skips only that
    // record and the following ones are still logged. Check if aya-log can be
    // improved upstream to report or skip bad records instead of panicking.
    while std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| logger.flush())).is_err() {
        log::error!("{module_name}: dropped a malformed eBPF log record");
    }
}
