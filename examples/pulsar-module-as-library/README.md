# Using a Pulsar module as a library

Every Pulsar module can be used by itself as a library for extracting events
from the Linux kernel.

In this example we use `network-monitor` for intercepting port bind events.
```
$ cargo build && sudo ./target/debug/examples/pulsar-module-as-library
23559805090354 - 43162 bind on 0.0.0.0:8000 (TCP)
23563534494178 - 32574 bind on 0.0.0.0:0 (TCP)
23563567897141 - 32574 bind on 172.19.0.1:0 (UDP)
23563567917920 - 32574 bind on 192.168.1.163:0 (UDP)
23563567927081 - 32574 bind on 192.168.1.227:0 (UDP)
23564813614814 - 1278 bind on 0.0.0.0:0 (TCP)
```

## How to do it

Add a dependency to the module you need. Since we're not exporting to crates.io,
it's best to add it as a git dependency. You'll need two more dependencies for
interacting with pulsar modules: `bpf-common` (eBPF configuration) and tokio.

```
network-monitor = { git = "https://github.com/exein-io/pulsar", rev = "797f68641ed92b35b152e0d147b9cdcf3bfa49e5" }
bpf-common = { git = "https://github.com/exein-io/pulsar", rev = "797f68641ed92b35b152e0d147b9cdcf3bfa49e5" }
tokio = { version = "1", features = ["full"] }
```

Then we'll define a configuration for the eBPF program. This will disable map
pinning (a feature used to share maps in eBPF programs which is needed by the
pulsar agent for process filtering), use a 512 pages PerfArray size and disable
`/sys/kernel/debug/tracing/trace_pipe` logging.
This configuration is good for this use-case, no need to change it unless you
have specific reasons.
```rust
    let ctx = BpfContext::new(Pinning::Disabled, 512, BpfLogLevel::Disabled).unwrap();
```

Then we'll create a `tokio::sync::mpsc` channel and pass the sender side to our
module.
```rust
let (tx, mut rx) = mpsc::channel(100);
let _program = network_monitor::program(ctx, tx)
    .await
    .expect("initialization failed");
```

Finally, we can consume events by reading on the receiver:
```rust
while let Some(msg) = rx.recv().await {
```
