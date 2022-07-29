# New eBPF probe tutorial

This tutorial goes through the development of a simple Pulsar module
that watches for new file creations. For a complete and working example,
see the [file-system-monitor](../modules/file-system-monitor/) module.

## Locating the best hook point with bpftrace

[bpftrace](https://github.com/iovisor/bpftrace) is a great tool for trying out the
various eBPF connection points. If you haven't yet, go check the 
[one-liner tutorial](https://github.com/iovisor/bpftrace/blob/master/docs/tutorial_one_liners.md).

When trying out new things, you start by looking for existing solutions. Key examples include the
[bpftrace](https://github.com/iovisor/bpftrace#tools)
and [bcc](https://github.com/iovisor/bcc/#tools) tool collections. You may then consider moving 
to other tracing and security software using eBPF such as 
[Tracee](https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c),
[lockc](https://github.com/lockc-project/lockc) or others.

Going back to our example, it turns out we can intercept file creations using the `security_inode_create` function:

```
sudo bpftrace -e 'kfunc:security_inode_create { printf("%s: %s\n", comm, str(args->dentry->d_name.name))}'
```

If you are curious about the various interesting hook points you can check out the
[LSM attach points](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hooks.h).

With all the necessary information gathered with the help of `bpftrace`, we can start the actual development.

## Development

We create a new Rust crate and we'll call it `file_created`.

```
[package]
name = "file_created"
version = "0.1.0"
edition = "2021"

[dependencies]
bpf-common = { path = "../../bpf-common" }
pulsar-core = { path = "../../pulsar-core" }
nix = "0.24.0"
tokio = { version = "1", features = ["full"] }

[build-dependencies]
bpf-common = { path = "../../bpf-common", features = ["build"] }

[dev-dependencies]
bpf-common = { path = "../../bpf-common", features = ["test-utils"] }
serial_test = { version = "0.6.0" }
```

The most important dependency is `bpf-common`, which re-exports [aya](https://github.com/aya-rs/aya)
and contains some useful utilities for running, building and testing probes.

Next we create write a simple eBPF program, we'll name it `probe.bpf.c`.
```c
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/security_inode_create")
int security_inodei_create(struct pt_regs *ctx) {
  return 0;
}
```

We create `build.rs` in order to build the program.

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_common::builder::build("probe.bpf.c")
}
```

The module implementation in Rust is also relatively short.

```rust
use std::fmt;

use bpf_common::{
    aya::include_bytes_aligned, parsing::StringArray, program::BpfContext, BpfSender, Program,
    ProgramBuilder, ProgramError,
};

pub async fn program(
    ctx: BpfContext,
    sender: impl BpfSender<EventT>,
) -> Result<Program, ProgramError> {
    let program = ProgramBuilder::new(
        ctx,
        "file_created",
        include_bytes_aligned!(concat!(env!("OUT_DIR"), "/probe.bpf.o")).into(),
    )
    .kprobe("security_inode_create")
    .start()
    .await?;
    program.read_events("events", sender).await?;
    Ok(program)
}

const NAME_MAX: usize = 264;
#[repr(C)]
pub enum EventT {
    FileCreated { filename: StringArray<NAME_MAX> },
}

impl fmt::Display for EventT {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventT::FileCreated { filename } => write!(f, "{}", filename),
        }
    }
}
```

The central part of the module is the `program` function, which:
- takes a `BpfContext` containing general Bpf settings, like BTF information and map pinning configuration.
  Just pass it down to `bpf_common::ProgramBuilder::new`.
- takes a `BpfSender`—the channel where we'll send the generated events. It's a trait so that
  you can use whatever data structure you want for your application: modules can be used inside Pulsar,
  but can also be used by themself. The [probe](../pulsar/bin/probe.rs) binary shows how
  you can use our modules without running the full agent.
- returns a `bpf_common::Program`. The application will keep sending `EventT` events over the `sender`
  channel until the program handle is dropped.

This implementation delegates all repetitive tasks to `bpf_common::ProgramBuilder::new()` which takes the
eBPF configuration, a name used for logging purposes and the compiled eBPF program binary.

We attach the program to the `security_inode_create` kprobe and start it.
Finally, we forward all events read from the `events` map to the `sender`
channel.

The most commonly used map type is `BPF_MAP_TYPE_PERF_EVENT_ARRAY` and `Program::read_events(sender)`
can be used to forward all generated events to the sender channel.
In case it's needed, `Program` also has a `poll` method for consuming eBPF HashMaps.

The application is almost ready to use and you should refer to the 
[`probe` binary](https://github.com/Exein-io/pulsar-experiments/blob/cleanup/pulsar/bin/probe.rs) 
for a simple way to link a and run it.

We can now implement `probe.bpf.c` to get this example to work. 

```C
#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

#define NAME_MAX 264

struct event_t {
  u64 timestamp;
  pid_t pid;
  u32 _event;
  char filename[NAME_MAX];
};

struct bpf_map_def SEC("maps/event") eventmem = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event_t),
    .max_entries = 1,
};

// used to send events to userspace
struct bpf_map_def SEC("maps/events") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(u32),
    .max_entries = 0,
};

SEC("kprobe/security_inode_create")
int security_inodei_create(struct pt_regs *ctx) {
  pid_t tgid = bpf_get_current_pid_tgid() >> 32;

  struct qstr q;
  u32 key = 0;
  struct event_t *event = bpf_map_lookup_elem(&eventmem, &key);
  if (!event)
	  return 0;
  struct dentry *dentry = PT_REGS_PARM2(ctx);
  bpf_probe_read_kernel(&q, sizeof(q), &dentry->d_name);
  bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), q.name);
  event->timestamp = bpf_ktime_get_ns();
  event->pid = tgid;
  event->_event = 0;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event_t));
  return 0;
}
```

The `struct event_t` layout must match the event defined in Rust, plus a timestamp, the process id
and the enum variant. For more details see the `BpfEvent` usage inside `Program`.

## Testing probes

Testing the eBPF program makes our edit-compile-test cycles much quicker to execute. It also enables us to spot 
regressions quickly and easily. The `TestRunner` struct makes it simple to run code to trigger a eBPF event and 
check it matches the expectations.

```rust
#[cfg(test)]
mod tests {
    use bpf_common::{event_check, test_runner::TestRunner};

    use super::*;

    #[tokio::test]
    async fn file_name() {
        let fname = "file_name_1";
        let path = "/tmp/file_name_1";
        TestRunner::with_ebpf(program)
            .run(|| {
                let _ = std::fs::remove_file(path);
                std::fs::File::create(path).expect("creating file failed");
            })
            .await
            .expect_event(event_check!(
                EventT::FileCreated,
                (filename, fname.into(), "filename")
            ));
    }
}
```

See the existing modules 
[`lib.rs`](https://github.com/Exein-io/pulsar-experiments/blob/37491068631e83f2df9dc74ed42ad0775d2cbd8f/modules/file-system-monitor/src/lib.rs#L164-L223) 
for more examples. All Pulsar modules must include an appropriate test suite. This makes it simple to spot 
incompatibilities when porting Pulsar to a new targets.

## Pulsar Integration 

What we've written so far is a standalone Rust module for intercepting file creation events.
In order to integrate it to the agent, we have to write a `PulsarModule` factory function that 
is added to the main file.

```rust
pub mod pulsar {
    use super::*;
    use pulsar-core::pdk::{
        CleanExit, ModuleContext, ModuleError, Payload, PulsarModule, ShutdownSignal, Version,
    };

    pub fn file_created() -> PulsarModule {
        PulsarModule::new(
            "file-created",
            Version::new(0, 0, 1),
            file_created_task,
        )
    }

    async fn file_created_task(
        ctx: ModuleContext,
        mut shutdown: ShutdownSignal,
    ) -> Result<CleanExit, ModuleError> {
        let _program = program(ctx.get_bpf_context(), ctx.get_sender()).await?;
        shutdown.recv().await
    }

    impl From<EventT> for Payload {
        fn from(data: EventT) -> Self {
            match data {
                EventT::FileCreated { filename } => Payload::FileCreated {
                    filename: filename.to_string(),
                },
            }
        }
    }
}
```

`file_created_task` is the async function that runs our module until the Pulsar agent sends us
the shutdown signal. By dropping `_program` we shut down the eBPF program and stop producing events.

All modules communicate using the agent's message bus, where [events](../pulsar-core/src/event.rs)
are sent and received.
Since we're writing a producer module, we'll get a sender with the `ModuleContext::get_sender()` method.
We can use that channel as a `BpfSender` for `bpf_common::Program` because we've implemented a conversion
method for transforming the module-specific and C-compatibile `EventT` into a `Payload`, which is the enum
with all the Pulsar events. We don't have to worry about process id and timestamp because headers will be
automatically filled by `bpf_common::Program`.


## Conclusion

We've built a eBPF probe which writes events into a perf event map. These events are then read by our
module and shared on the agent's bus.

Key take-aways:
- `bpf-common` contains a collection of tools built on top of [aya](https://github.com/aya-rs/aya), they reduce boilerplate
  and help writing tests. 
- A module can be used as part of Pulsar or by itself. A generic Rust application could reuse a
  particular probe without depending on the Pulsar agent.
- Writing tests first is the best way to develop a new probe.
