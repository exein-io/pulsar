use std::fmt;

use bpf_common::{
    aya::include_bytes_aligned, parsing::StringArray, program::BpfContext, BpfSender, Program,
    ProgramBuilder, ProgramError,
};
use nix::libc;

const MODULE_NAME: &str = "file-system-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<FsEvent>,
) -> Result<Program, ProgramError> {
    let program = ProgramBuilder::new(
        ctx,
        MODULE_NAME,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
    )
    .kprobe("security_inode_create")
    .kprobe("security_inode_unlink")
    .kprobe("security_file_open")
    .start()
    .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

const NAME_MAX: usize = 1024;
#[repr(C)]
pub enum FsEvent {
    FileCreated {
        filename: StringArray<NAME_MAX>,
    },
    FileDeleted {
        filename: StringArray<NAME_MAX>,
    },
    FileOpened {
        filename: StringArray<NAME_MAX>,
        flags: Flags,
    },
}

impl fmt::Display for FsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsEvent::FileCreated { filename } => write!(f, "created {}", filename),
            FsEvent::FileDeleted { filename } => write!(f, "deleted {}", filename),
            FsEvent::FileOpened { filename, flags } => {
                write!(f, "open {} ({})", filename, flags.0)
            }
        }
    }
}

const FLAGS: [(i32, &str); 22] = [
    (libc::O_APPEND, "APPEND"),
    (libc::O_ASYNC, "ASYNC"),
    (libc::O_CLOEXEC, "CLOEXEC"),
    (libc::O_CREAT, "CREAT"),
    (libc::O_DIRECT, "DIRECT"),
    (libc::O_DIRECTORY, "DIRECTORY"),
    (libc::O_DSYNC, "DSYNC"),
    (libc::O_EXCL, "EXCL"),
    (libc::O_LARGEFILE, "LARGEFILE"),
    (libc::O_NDELAY, "NDELAY"),
    (libc::O_NOATIME, "NOATIME"),
    (libc::O_NOCTTY, "NOCTTY"),
    (libc::O_NOFOLLOW, "NOFOLLOW"),
    (libc::O_NONBLOCK, "NONBLOCK"),
    (libc::O_PATH, "PATH"),
    (libc::O_RDONLY, "RDONLY"),
    (libc::O_RDWR, "RDWR"),
    (libc::O_RSYNC, "RSYNC"),
    (libc::O_SYNC, "SYNC"),
    (libc::O_TMPFILE, "TMPFILE"),
    (libc::O_TRUNC, "TRUNC"),
    (libc::O_WRONLY, "WRONLY"),
];

#[derive(PartialEq, Eq)]
pub struct Flags(i32);

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(")?;
        for (flag, name) in FLAGS {
            if (flag & self.0) != 0 {
                write!(f, "{};", name)?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.0, self)
    }
}

pub mod pulsar {

    use std::{
        os::unix::prelude::FileTypeExt,
        time::{Duration, Instant},
    };

    use super::*;
    use pulsar_core::pdk::{
        CleanExit, ConfigError, Event, ModuleConfig, ModuleContext, ModuleError, ModuleSender,
        Payload, PulsarModule, ShutdownSignal, Version,
    };
    use tokio::{fs::File, io::AsyncReadExt};

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 0, 1), fs_monitor_task)
    }

    async fn fs_monitor_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let _program = program(ctx.get_bpf_context(), ctx.get_sender()).await?;
        let mut receiver = ctx.get_receiver();
        let mut rx_config = ctx.get_cfg::<Config>();
        let mut config = ctx.get_cfg::<Config>().borrow().clone()?;
        let sender = ctx.get_sender();
        loop {
            // enable receiver only if the elf checker is enabled
            let receiver_recv = async {
                if config.elf_check_enabled {
                    receiver.recv().await
                } else {
                    std::future::pending().await
                }
            };
            tokio::select! {
                Ok(msg) = receiver_recv => {
                    check_elf(&sender, &config, msg.as_ref()).await;
                }
                _ = rx_config.changed() => {
                    config = rx_config.borrow().clone()?;
                }
                r = shutdown.recv() => return r,
            }
        }
    }

    impl From<FsEvent> for Payload {
        fn from(data: FsEvent) -> Self {
            match data {
                FsEvent::FileCreated { filename } => Payload::FileCreated {
                    filename: filename.to_string(),
                },
                FsEvent::FileDeleted { filename } => Payload::FileDeleted {
                    filename: filename.to_string(),
                },
                FsEvent::FileOpened { filename, flags } => Payload::FileOpened {
                    filename: filename.to_string(),
                    flags: flags.0,
                },
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct Config {
        elf_check_enabled: bool,
        elf_check_whitelist: Vec<String>,
    }

    impl TryFrom<&ModuleConfig> for Config {
        type Error = ConfigError;

        fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
            Ok(Config {
                elf_check_enabled: config.with_default("elf_check_enabled", true)?,
                elf_check_whitelist: config.get_list_with_default(
                    "elf_check_whitelist",
                    vec![
                        String::from("/proc"),
                        String::from("/sys"),
                        String::from("/dev"),
                    ],
                )?,
            })
        }
    }

    /// Check if an opened file is an ELF
    async fn check_elf(sender: &ModuleSender, config: &Config, event: &Event) {
        if let Payload::FileOpened { filename, flags } = &event.payload {
            let now = Instant::now();
            let should_check = !config
                .elf_check_whitelist
                .iter()
                .any(|path| filename.starts_with(path));
            if should_check && is_elf(filename).await {
                sender.send_derived_event(
                    event,
                    Payload::ElfOpened {
                        filename: filename.to_string(),
                        flags: *flags,
                    },
                );
            }
            let elapsed = now.elapsed();
            if elapsed > Duration::from_millis(10) {
                log::warn!(
                    "checking if {:?} is an elf file took {} millis",
                    filename,
                    elapsed.as_millis()
                );
            }
        }
    }

    const ELF_MAGIC: [u8; 4] = [0x7F, 0x45, 0x4C, 0x46];

    /// Returns true if the file is an ELF executable.
    pub async fn is_elf(filename: &str) -> bool {
        if let Ok(mut file) = File::open(filename).await {
            match file.metadata().await {
                Ok(metadata) => {
                    let t = metadata.file_type();
                    if t.is_dir()
                        || t.is_char_device()
                        || t.is_block_device()
                        || t.is_symlink()
                        || t.is_fifo()
                        || t.is_socket()
                    {
                        return false;
                    }
                }
                Err(_) => return false,
            }
            let mut buffer = [0; 4];
            if file.read_exact(&mut buffer).await.is_ok() {
                return buffer == ELF_MAGIC;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use bpf_common::{event_check, test_runner::TestRunner};

    use super::*;

    #[tokio::test]
    #[serial_test::serial]
    async fn file_name() {
        let path = "/tmp/file_name_1";
        TestRunner::with_ebpf(program)
            .run(|| {
                let _ = std::fs::remove_file(path);
                std::fs::File::create(path).expect("creating file failed");
            })
            .await
            .expect_event(event_check!(
                FsEvent::FileCreated,
                (filename, path.into(), "filename")
            ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn unlink_file() {
        let path = "/tmp/unlink_file";
        std::fs::write(path, b"").unwrap();
        TestRunner::with_ebpf(program)
            .run(|| nix::unistd::unlink(path).unwrap())
            .await
            .expect_event(event_check!(
                FsEvent::FileDeleted,
                (filename, path.into(), "filename")
            ));
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn open_file() {
        let path = "/tmp/open_file";
        // See include/linux/fs.h
        const FMODE_OPENED: i32 = 32768;

        std::fs::write(path, b"hello_world").unwrap();
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        TestRunner::with_ebpf(program)
            .run(|| {
                options.open(path).unwrap();
            })
            .await
            .expect_event(event_check!(
                FsEvent::FileOpened,
                (filename, path.into(), "filename"),
                (flags, Flags(libc::O_RDWR | FMODE_OPENED), "open flags")
            ));
    }
}
