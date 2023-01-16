use std::fmt;

use bpf_common::{
    aya::include_bytes_aligned, feature_autodetect::lsm::lsm_supported, parsing::BufferIndex,
    program::BpfContext, test_runner::ComparableField, BpfSender, Program, ProgramBuilder,
    ProgramError,
};

const MODULE_NAME: &str = "file-system-monitor";

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<FsEvent>,
) -> Result<Program, ProgramError> {
    let mut builder = ProgramBuilder::new(
        ctx,
        MODULE_NAME,
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
    );
    // LSM hooks provide the perfet intercept point for file system operations.
    // If LSM eBPF programs is not supported, we'll attach to the same kernel
    // functions, but using kprobes.
    if lsm_supported().await {
        log::info!("Loading LSM programs");
        builder = builder
            .lsm("path_mknod")
            .lsm("path_unlink")
            .lsm("path_mkdir")
            .lsm("path_rmdir")
            .lsm("path_rename")
            .lsm("file_open")
            .lsm("path_link")
            .lsm("path_symlink");
    } else {
        log::info!("LSM programs not supported. Falling back to kprobes");
        builder = builder
            .kprobe("security_path_mknod")
            .kprobe("security_path_unlink")
            .kprobe("security_path_mkdir")
            .kprobe("security_path_rmdir")
            .kprobe("security_path_rename")
            .kprobe("security_file_open")
            .kprobe("security_path_link")
            .kprobe("security_path_symlink");
    }
    let mut program = builder.start().await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

#[repr(C)]
pub enum FsEvent {
    FileCreated {
        filename: BufferIndex<str>,
    },
    FileDeleted {
        filename: BufferIndex<str>,
    },
    DirCreated {
        filename: BufferIndex<str>,
    },
    DirDeleted {
        filename: BufferIndex<str>,
    },
    FileOpened {
        filename: BufferIndex<str>,
        flags: i32,
    },
    FileLink {
        source: BufferIndex<str>,
        destination: BufferIndex<str>,
        hard_link: bool,
    },
    FileRename {
        source: BufferIndex<str>,
        destination: BufferIndex<str>,
    },
}

impl fmt::Display for FsEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsEvent::FileCreated { filename } => write!(f, "created {:?}", filename),
            FsEvent::FileDeleted { filename } => write!(f, "deleted {:?}", filename),
            FsEvent::DirCreated { filename } => write!(f, "created dir {:?}", filename),
            FsEvent::DirDeleted { filename } => write!(f, "deleted dir {:?}", filename),
            FsEvent::FileOpened { filename, flags } => {
                write!(f, "open {:?} ({})", filename, flags)
            }
            FsEvent::FileLink {
                source,
                destination,
                hard_link,
            } => write!(
                f,
                "{} {:?} -> {:?}",
                if *hard_link { "hardlink" } else { "symlink" },
                source,
                destination
            ),
            FsEvent::FileRename {
                source,
                destination,
            } => write!(f, "rename {:?} -> {:?}", source, destination),
        }
    }
}

pub mod pulsar {

    use std::{
        os::unix::prelude::FileTypeExt,
        time::{Duration, Instant},
    };

    use super::*;
    use bpf_common::{parsing::IndexError, program::BpfEvent};
    use pulsar_core::{
        event::FileFlags,
        pdk::{
            CleanExit, ConfigError, Event, IntoPayload, ModuleConfig, ModuleContext, ModuleError,
            ModuleSender, Payload, PulsarModule, ShutdownSignal, Version,
        },
    };
    use tokio::{fs::File, io::AsyncReadExt};

    pub fn module() -> PulsarModule {
        PulsarModule::new(MODULE_NAME, Version::new(0, 4, 0), fs_monitor_task)
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

    impl IntoPayload for FsEvent {
        type Error = IndexError;

        fn try_into_payload(data: BpfEvent<Self>) -> Result<Payload, Self::Error> {
            let BpfEvent {
                payload, buffer, ..
            } = data;
            Ok(match payload {
                FsEvent::FileCreated { filename } => Payload::FileCreated {
                    filename: filename.string(&buffer)?,
                },
                FsEvent::FileDeleted { filename } => Payload::FileDeleted {
                    filename: filename.string(&buffer)?,
                },
                FsEvent::DirCreated { filename } => Payload::DirCreated {
                    dirname: filename.string(&buffer)?,
                },
                FsEvent::DirDeleted { filename } => Payload::DirDeleted {
                    dirname: filename.string(&buffer)?,
                },
                FsEvent::FileOpened { filename, flags } => Payload::FileOpened {
                    filename: filename.string(&buffer)?,
                    flags: FileFlags::from_raw_unchecked(flags),
                },
                FsEvent::FileLink {
                    source,
                    destination,
                    hard_link,
                } => Payload::FileLink {
                    source: source.string(&buffer)?,
                    destination: destination.string(&buffer)?,
                    hard_link,
                },
                FsEvent::FileRename {
                    source,
                    destination,
                } => Payload::FileRename {
                    source: source.string(&buffer)?,
                    destination: destination.string(&buffer)?,
                },
            })
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
        if let Payload::FileOpened { filename, flags } = event.payload() {
            let now = Instant::now();
            let should_check = !config
                .elf_check_whitelist
                .iter()
                .any(|path| filename.starts_with(path));
            if should_check && is_elf(filename).await {
                sender.send_derived(
                    event,
                    Payload::ElfOpened {
                        filename: filename.to_string(),
                        flags: flags.clone(),
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

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use std::{env::temp_dir, fs::OpenOptions};

    use super::*;
    use bpf_common::{
        event_check,
        test_runner::{TestCase, TestRunner, TestSuite},
    };
    use pulsar_core::kernel;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "file-system-monitor",
            tests: vec![
                open_file(),
                create_file(),
                unlink_file(),
                symlink(),
                hardlink(),
                mkdir(),
                rmdir(),
                rename(),
            ],
        }
    }

    fn create_file() -> TestCase {
        TestCase::new("create_file", async {
            let path = temp_dir().join("file_name_1");
            TestRunner::with_ebpf(program)
                .run(|| {
                    _ = std::fs::remove_file(&path);
                    std::fs::File::create(&path).expect("creating file failed");
                })
                .await
                .expect_event(event_check!(
                    FsEvent::FileCreated,
                    (filename, path.to_str().unwrap().into(), "filename")
                ))
                .report()
        })
    }

    fn unlink_file() -> TestCase {
        TestCase::new("unlink_file", async {
            let path = temp_dir().join("unlink_file");
            _ = std::fs::remove_file(&path);
            std::fs::write(&path, b"").unwrap();
            TestRunner::with_ebpf(program)
                .run(|| nix::unistd::unlink(path.to_str().unwrap()).unwrap())
                .await
                .expect_event(event_check!(
                    FsEvent::FileDeleted,
                    (filename, path.to_str().unwrap().into(), "filename")
                ))
                .report()
        })
    }

    fn open_file() -> TestCase {
        TestCase::new("open_file", async {
            let path = temp_dir().join("open_file");
            // See include/linux/fs.h
            const FMODE_OPENED: i32 = 32768;

            _ = std::fs::remove_file(&path);
            std::fs::write(&path, b"hello_world").unwrap();
            let mut options = OpenOptions::new();
            options.read(true).write(true);
            TestRunner::with_ebpf(program)
                .run(|| {
                    options.open(&path).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::FileOpened,
                    (filename, path.to_str().unwrap().into(), "filename"),
                    (
                        flags,
                        kernel::file::flags::O_RDWR | FMODE_OPENED,
                        "open flags"
                    )
                ))
                .report()
        })
    }

    fn symlink() -> TestCase {
        TestCase::new("symlink", async {
            let source = temp_dir().join("source");
            let destination = temp_dir().join("destination");
            _ = std::fs::remove_file(&source);
            _ = std::fs::remove_file(&destination);
            TestRunner::with_ebpf(program)
                .run(|| {
                    std::os::unix::fs::symlink(&destination, &source).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::FileLink,
                    (source, source.to_str().unwrap().into(), "source"),
                    (
                        destination,
                        destination.to_str().unwrap().into(),
                        "destination"
                    ),
                    (hard_link, false, "hard_link")
                ))
                .report()
        })
    }

    fn hardlink() -> TestCase {
        TestCase::new("hardlink", async {
            let source = temp_dir().join("source");
            let destination = temp_dir().join("destination");
            _ = std::fs::remove_file(&source);
            _ = std::fs::remove_file(&destination);
            // destination must exist for an hardlink to be created
            std::fs::write(&destination, b"hello world").unwrap();
            TestRunner::with_ebpf(program)
                .run(|| {
                    std::fs::hard_link(&destination, &source).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::FileLink,
                    (source, source.to_str().unwrap().into(), "source"),
                    (
                        destination,
                        destination.to_str().unwrap().into(),
                        "destination"
                    ),
                    (hard_link, true, "hard_link")
                ))
                .report()
        })
    }

    fn mkdir() -> TestCase {
        TestCase::new("mkdir", async {
            let dirname = temp_dir().join("mkdir");
            _ = std::fs::remove_dir_all(&dirname);
            TestRunner::with_ebpf(program)
                .run(|| {
                    std::fs::create_dir(&dirname).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::DirCreated,
                    (filename, dirname.to_str().unwrap().into(), "name")
                ))
                .report()
        })
    }

    fn rmdir() -> TestCase {
        TestCase::new("rmdir", async {
            let dirname = temp_dir().join("rmdir");
            _ = std::fs::remove_dir_all(&dirname);
            std::fs::create_dir(&dirname).unwrap();
            TestRunner::with_ebpf(program)
                .run(|| {
                    std::fs::remove_dir_all(&dirname).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::DirDeleted,
                    (filename, dirname.to_str().unwrap().into(), "name")
                ))
                .report()
        })
    }

    fn rename() -> TestCase {
        TestCase::new("rename", async {
            let source = temp_dir().join("rename_source");
            let destination = temp_dir().join("rename_destination");
            _ = std::fs::remove_file(&source);
            _ = std::fs::remove_file(&destination);
            std::fs::write(&source, b"hello world").unwrap();
            TestRunner::with_ebpf(program)
                .run(|| {
                    std::fs::rename(&source, &destination).unwrap();
                })
                .await
                .expect_event(event_check!(
                    FsEvent::FileRename,
                    (source, source.to_str().unwrap().into(), "source"),
                    (
                        destination,
                        destination.to_str().unwrap().into(),
                        "destination"
                    )
                ))
                .report()
        })
    }
}
