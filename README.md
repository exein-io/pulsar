<div align="center">
  <img width="300" src="res/pulsar-logo-black.png#gh-light-mode-only" alt="Pulsar dark logo">
  <img width="300" src="res/pulsar-logo-white.png#gh-dark-mode-only" alt="Pulsar light logo">
  <p>
  A highly modular and blazing fast eBPF-based runtime security agent framework for the IoT.
  </p>
  <p>
    <a href="https://github.com/Exein-io/pulsar/actions/workflows/test.yml">
      <img src="https://github.com/Exein-io/pulsar/actions/workflows/test.yml/badge.svg?branch=main" alt="Lint and Tests">
    </a>
    <a href="https://discord.gg/ZrySDqhBtZ"><img src="https://img.shields.io/discord/986983233256321075?color=%2331c753&logo=discord">
    <a href="https://opensource.org/licenses/Apache-2.0">
      <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
      <img src="https://img.shields.io/badge/License-GPL--2.0-blue.svg" alt="License">
    </a>
  </p>
</div>

## Quickstart

The following are a set of steps to quickly get started with Pulsar on a
Debian-based distribution running kernel version 5.5 or higher with BPF
and BTF enabled ([requirements](#minimum-kernel-requirements)).

```sh
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Clang (needed for eBPF compilation)
sudo apt install clang

# Get and build Pulsar
git clone https://github.com/Exein-io/pulsar.git
cd pulsar
cargo test
cargo xtask test
cargo build --release

# Install files
sudo cp scripts/pulsar scripts/pulsard target/release/pulsar-exec /usr/bin/
sudo chmod +x /usr/bin/pulsar /usr/bin/pulsard

# Run it
sudo pulsard
```

## Architecture

Pulsar is powered by the [`pulsard`](./pulsar/src/pulsard/daemon.rs) 
daemon — responsible for managing the state of [modules](./modules/) 
that come with Pulsar.

Functionality is enabled through the use of Pulsar modules. Modules are sub-
programs that perform specific operations (e.g. monitoring filesystem access) 
that are loaded into Pulsar at runtime and enable the use of eBPF to power
most modules.

Internally every module has access to the shared message bus and can either 
produce or consume [events](./pulsar-core/src/event.rs). It's a broadcast MPMC 
channel (multi-producer, multi consumer) where every subscriber will receive 
every message. This allows to build modular code with a clear separation of 
concerns.

The [probe tutorial](./bpf-common/ProbeTutorial.md) highlights how to build an 
eBPF probe and integrate it into Pulsar via the module system.

## Kernel Requirements

### Minimum

Currently Pulsar requires at least kernel version 5.5 with BPF and BTF enabled.

We're requiring 5.5 because we use `BPF_CORE_READ`, which under the hood uses
`bpf_probe_read_kernel`. To support older kernel versions we may use the older
and generic `bpf_probe_read`.

The following kernel configurations must be enabled:
```
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_FUNCTION_TRACER=y
CONFIG_FTRACE_SYSCALLS=y
```

See <https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md>

### Recommended

For best results we recommend a kernel >= 5.7 with all the above configuration enabled plus the following: 
```
CONFIG_BPF_LSM=y
```

This configuration only is available from 5.7.

With this configuration enabled Pulsar uses the more powerful and stable BPF LSM hooks. If you use have BPF_LSM disabled it uses Kprobes as fallback.

## Advanced

### Running without installing

```sh
cargo xtask pulsard
```

Which is the same as

```sh
cargo build
sudo ./target/debug/pulsar-exec pulsard
```

### Integration tests

In order to make sure your system is fully surpported, run the [test
suite](./test-suite).

```sh
cargo xtask test
```

Which is the same as

```sh
cargo build
sudo ./target/debug/test-suite
```

### Single probe runner

Probes can be run in isolation by running the following. 

```sh
cargo xtask probe file-system-monitor
```

Which is the same as

```sh
cargo build
sudo ./target/debug/probe file-system-monitor
```

## Contributing

If you're interested in contributing to Pulsar — thank you!

We have a [contributing guide](CONTRIBUTING.md) which will help you getting involved in the project.

## Community

Join the Pulsar [Discord server](https://discord.gg/MQgaTPef7a) to chat with developers, maintainers, and the whole community. You can also drop any question about Pulsar on the official [GitHub discussions](https://github.com/Exein-io/pulsar/discussions) or use the [GitHub issues](https://github.com/Exein-io/pulsar/issues) for feature requests and bug reports.

## License

Pulsar is [licensed](./LICENSE) under two licenses — Pulsar userspace code is licensed under [APACHE-2.0](./LICENSES/LICENSE-APACHE-2.0). Pulsar eBPF probes are licensed under [GPL-2.0](./LICENSES/LICENSE-GPL-2.0).
