//! Tests of `probes/process.bpf.c`.

use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command},
    thread,
    time::Duration,
};

use anyhow::Context;
use bpf_filtering::{config::Rule, maps::Image};
use next_core::payload::Argv;
use next_test_suite_harness::{
    Test, TestResult, Verdict, Watched,
    daemon::TestDaemon,
    expect::{expect, expect_lost, only},
    helper::{self, Helper},
    pattern::{ChangeParent, CredentialsChange, Exec, Exit, Fork},
    watch,
};
use nix::{
    sys::{prctl, wait::waitpid},
    unistd::{Gid, Pid, SysconfVar, Uid, getgid, getpid, getppid, getuid, setgid, setuid, sysconf},
};

pub fn tests() -> Vec<Test> {
    vec![
        Test::new("fork_exit", || Box::pin(fork_exit())),
        Test::new("exec_event", || Box::pin(exec_event())),
        Test::new("exec_event_argv_fits", || Box::pin(exec_event_argv_fits())),
        Test::new("exec_event_argv_too_long", || {
            Box::pin(exec_event_argv_too_long())
        }),
        Test::new("relative_exec_event", || Box::pin(relative_exec_event())),
        Test::new("exit_event_no_thread", || Box::pin(exit_event_no_thread())),
        Test::new("exit_event_from_thread", || {
            Box::pin(exit_event_from_thread())
        }),
        Test::new("parent_change", || Box::pin(parent_change())),
        Test::new("credentials_change_uid", || {
            Box::pin(credentials_change_uid())
        }),
        Test::new("credentials_change_gid", || {
            Box::pin(credentials_change_gid())
        }),
        Test::new("seeded_image", || Box::pin(seeded_image())),
        Test::new("lost_records", || Box::pin(lost_records())),
        Test::new("seeding_gap", || Box::pin(seeding_gap())).expected_failure(
            "children an ignored process forks between the attach of the probes and \
             the read of /proc stay tracked",
            None,
        ),
    ]
}

/// What exec tests run: not this binary, so an exec changes the image.
const EXEC_TARGET: &str = "test-suite-next-exec";

/// The argument that makes [`EXEC_TARGET`] fork until it is killed.
const FORK_LOOP: &str = "fork-loop";

/// `HALF_BUFFER_MASK` of `buffer.bpf.h`: an argv this long, NULs included, or
/// longer is cut to one byte less.
const HALF_BUFFER_MASK: usize = 16384 / 2 - 1;

/// An id no process of the suite has.
const NEW_ID: u32 = 666;

/// How often a process waiting for its new parent looks.
const POLL: Duration = Duration::from_millis(1);

/// The absolute path of [`EXEC_TARGET`], built next to this binary.
fn exec_target() -> anyhow::Result<String> {
    let path = std::env::current_exe()?.with_file_name(EXEC_TARGET);
    let path = path
        .canonicalize()
        .with_context(|| format!("finding {}", path.display()))?;
    Ok(path.to_string_lossy().into_owned())
}

fn this_binary() -> anyhow::Result<String> {
    Ok(std::env::current_exe()?.to_string_lossy().into_owned())
}

fn argv(args: &[&str], truncated: bool) -> Option<Argv> {
    Some(Argv {
        args: args.iter().map(|arg| arg.to_string()).collect(),
        truncated,
    })
}

/// A child of a helper runs `path` with `argv`, in `dir` when it is given.
/// The result is the pid of the child.
async fn exec_in_child(
    dir: Option<String>,
    path: String,
    argv: Vec<String>,
) -> anyhow::Result<Watched<u32>> {
    watch((dir, path, argv), |(dir, path, argv)| {
        helper::fork_and_wait(|| {
            if let Some(dir) = dir {
                nix::unistd::chdir(dir.as_str()).expect("changing directory");
            }
            helper::exec(&path, &argv)
        })
    })
    .await
}

/// A child of the helper exits with a known code.
async fn fork_exit() -> TestResult {
    const EXIT_CODE: i32 = 42;
    let Watched {
        recording,
        pid: parent,
        result: child,
    } = watch((), |()| helper::fork_and_wait(|| EXIT_CODE)).await?;
    let image = this_binary()?;
    Ok(expect(
        &recording,
        &[
            &only(
                Fork::of(child)
                    .ppid(parent)
                    .uid(getuid().as_raw())
                    .gid(getgid().as_raw())
                    .header(|header| header.image(image)),
            ),
            &only(Exit::of(child).exit_code(EXIT_CODE as u32)),
        ],
    ))
}

/// A child of the helper runs another binary: the exec has its path and
/// arguments, and the events from then on its image.
async fn exec_event() -> TestResult {
    let path = exec_target()?;
    let args = [EXEC_TARGET, "-n"];
    let Watched {
        recording,
        result: child,
        ..
    } = exec_in_child(None, path.clone(), args.map(String::from).to_vec()).await?;
    Ok(expect(
        &recording,
        &[
            &only(
                Exec::of(child)
                    .filename(path.as_str())
                    .argc(args.len())
                    .argv(argv(&args, false))
                    .header(|header| header.image(path.as_str())),
            ),
            &Exit::of(child)
                .exit_code(0)
                .header(|header| header.image(path.as_str())),
        ],
    ))
}

/// An argument that makes the argv of [`EXEC_TARGET`] `len` bytes long.
fn padding(len: usize) -> String {
    // The NULs after `argv[0]` and after the padding.
    const NULS: usize = 2;
    "a".repeat(len - EXEC_TARGET.len() - NULS)
}

/// The longest argv that fits is read whole.
async fn exec_event_argv_fits() -> TestResult {
    let padding = padding(HALF_BUFFER_MASK - 1);
    let args = [EXEC_TARGET, padding.as_str()];
    let Watched {
        recording,
        result: child,
        ..
    } = exec_in_child(None, exec_target()?, args.map(String::from).to_vec()).await?;
    Ok(expect(
        &recording,
        &[&Exec::of(child).argc(args.len()).argv(argv(&args, false))],
    ))
}

/// An argv too long is cut where the buffer ends, and says so.
async fn exec_event_argv_too_long() -> TestResult {
    let padding = padding(HALF_BUFFER_MASK + 1000);
    let args = [EXEC_TARGET, padding.as_str()];
    let Watched {
        recording,
        result: child,
        ..
    } = exec_in_child(None, exec_target()?, args.map(String::from).to_vec()).await?;
    // One byte less than the mask: `argv[0]`, its NUL, and the padding cut.
    let kept = &padding[..HALF_BUFFER_MASK - 1 - EXEC_TARGET.len() - 1];
    Ok(expect(
        &recording,
        &[&Exec::of(child)
            .argc(args.len())
            .argv(argv(&[EXEC_TARGET, kept], true))],
    ))
}

/// An exec of a relative path has the absolute one.
async fn relative_exec_event() -> TestResult {
    let path = exec_target()?;
    let dir = Path::new(&path)
        .parent()
        .context("the exec target has no directory")?
        .to_string_lossy()
        .into_owned();
    let Watched {
        recording,
        result: child,
        ..
    } = exec_in_child(
        Some(dir),
        format!("./{EXEC_TARGET}"),
        vec![EXEC_TARGET.to_owned()],
    )
    .await?;
    Ok(expect(
        &recording,
        &[&only(
            Exec::of(child)
                .filename(path.as_str())
                .header(|header| header.image(path.as_str())),
        )],
    ))
}

/// A thread that ends isn't the exit of its process.
async fn exit_event_no_thread() -> TestResult {
    const EXIT_CODE: i32 = 7;
    let Watched {
        recording,
        result: child,
        ..
    } = watch((), |()| {
        helper::fork_and_wait(|| {
            thread::spawn(|| {}).join().expect("joining the thread");
            EXIT_CODE
        })
    })
    .await?;
    Ok(expect(
        &recording,
        &[&only(Exit::of(child).exit_code(EXIT_CODE as u32))],
    ))
}

/// A thread that exits the process, while the main thread waits, sets the
/// exit code.
async fn exit_event_from_thread() -> TestResult {
    const EXIT_CODE: i32 = 9;
    let Watched {
        recording,
        result: child,
        ..
    } = watch((), |()| {
        helper::fork_and_wait(|| {
            thread::spawn(|| std::process::exit(EXIT_CODE));
            loop {
                thread::park();
            }
        })
    })
    .await?;
    Ok(expect(
        &recording,
        &[&only(Exit::of(child).exit_code(EXIT_CODE as u32))],
    ))
}

/// The child of a process that exits gets the helper as its parent, since the
/// helper is a subreaper.
async fn parent_change() -> TestResult {
    let Watched {
        recording,
        pid: reaper,
        result: (parent, child),
    } = watch((), |()| {
        prctl::set_child_subreaper(true).expect("becoming a subreaper");
        let reaper = getpid();
        let (mut reader, mut writer) = std::io::pipe().expect("a pipe");
        let parent = helper::fork_and_wait(|| {
            let child = helper::fork(|| {
                // Exits only once adopted, so its exit comes after the change.
                while getppid() != reaper {
                    thread::sleep(POLL);
                }
                0
            });
            writer
                .write_all(&child.as_raw().to_ne_bytes())
                .expect("sending the pid of the child");
            0
        });
        let mut child = [0; size_of::<i32>()];
        reader
            .read_exact(&mut child)
            .expect("reading the pid of the child");
        let child = Pid::from_raw(i32::from_ne_bytes(child));
        waitpid(child, None).expect("waiting for the adopted child");
        (parent, child.as_raw() as u32)
    })
    .await?;
    Ok(expect(
        &recording,
        &[
            &Exit::of(parent),
            &only(ChangeParent::of(child).ppid(reaper)),
            &Exit::of(child),
        ],
    ))
}

/// A child of the helper changes its user: the change has the new user and
/// the old group, and the events from then on the new user.
async fn credentials_change_uid() -> TestResult {
    let Watched {
        recording,
        result: child,
        ..
    } = watch((), |()| {
        helper::fork_and_wait(|| {
            setuid(Uid::from_raw(NEW_ID)).expect("changing the user");
            0
        })
    })
    .await?;
    let gid = getgid().as_raw();
    Ok(expect(
        &recording,
        &[
            &only(CredentialsChange::of(child).uid(NEW_ID).gid(gid)),
            &Exit::of(child).header(|header| header.uid(NEW_ID).gid(gid)),
        ],
    ))
}

/// A child of the helper changes its group: the change has the old user and
/// the new group, and the events from then on the new group.
async fn credentials_change_gid() -> TestResult {
    let Watched {
        recording,
        result: child,
        ..
    } = watch((), |()| {
        helper::fork_and_wait(|| {
            setgid(Gid::from_raw(NEW_ID)).expect("changing the group");
            0
        })
    })
    .await?;
    let uid = getuid().as_raw();
    Ok(expect(
        &recording,
        &[
            &only(CredentialsChange::of(child).uid(uid).gid(NEW_ID)),
            &Exit::of(child).header(|header| header.uid(uid).gid(NEW_ID)),
        ],
    ))
}

/// A process started before the daemon has its image, read from /proc.
async fn seeded_image() -> TestResult {
    let Watched { recording, pid, .. } = watch((), |()| ()).await?;
    let image = this_binary()?;
    Ok(expect(
        &recording,
        &[&Exit::of(pid).header(|header| header.image(image))],
    ))
}

/// A ring of one page can't hold a burst of forks: records are lost, and the
/// daemon counts them.
async fn lost_records() -> TestResult {
    const FORKERS: usize = 4;
    // Not reaped until all are forked: many more and a VM of 1 GiB runs out
    // of tasks.
    const FORKS: usize = 1000;
    let page = sysconf(SysconfVar::PAGE_SIZE)?.context("no page size")?;
    let page = u32::try_from(page)?;
    let helper = Helper::spawn((), |()| {
        let forkers: Vec<_> = (0..FORKERS)
            .map(|_| {
                helper::fork(|| {
                    let children: Vec<_> = (0..FORKS).map(|_| helper::fork(|| 0)).collect();
                    for child in children {
                        waitpid(child, None).expect("waiting for a child");
                    }
                    0
                })
            })
            .collect();
        for forker in forkers {
            waitpid(forker, None).expect("waiting for a forker");
        }
    })?
    .run_timeout(Duration::from_secs(60));
    let daemon = TestDaemon::start_configured(|config| config.loader.ring_size = page).await?;
    let pid = helper.pid();
    helper.finish().await?;
    let recording = daemon.stop_after_exit(pid).await?;
    Ok(expect_lost(&recording))
}

/// Kills the process when dropped, so no test leaves it running.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

/// A process ignored with its children forks while the daemon starts: none of
/// its children is tracked.
async fn seeding_gap() -> TestResult {
    let target = exec_target()?;
    let marker = Helper::spawn((), |()| ())?;
    // Not a helper: it runs the exec target, which a rule can ignore, from
    // before the daemon starts. Command is safe in a multithreaded process.
    let forker = Killed(
        Command::new(&target)
            .arg(FORK_LOOP)
            .spawn()
            .context("starting the fork loop")?,
    );
    let forker_pid = forker.0.id();
    let rule = Rule {
        image: Image::try_from(target.into_bytes())?,
        track: false,
        with_children: true,
    };
    let daemon = TestDaemon::start_configured(|config| config.filtering.rules.push(rule)).await?;
    drop(forker);
    let pid = marker.pid();
    marker.finish().await?;
    let recording = daemon.stop_after_exit(pid).await?;

    let tracked: Vec<_> = recording
        .events
        .iter()
        .filter(|event| {
            event
                .header
                .subject
                .as_ref()
                .is_some_and(|subject| subject.ppid == forker_pid)
        })
        .collect();
    let verdict = match tracked.first() {
        None => Verdict::Passed,
        Some(first) => Verdict::Failed(format!(
            "{} events about children of the ignored {forker_pid}, the first: {}: {:?}",
            tracked.len(),
            first.header,
            first.payload
        )),
    };
    Ok(recording.outcome(verdict))
}
