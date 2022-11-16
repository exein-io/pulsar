<div align="center">
  <img width="300" src="res/pulsar-logo-black.png#gh-light-mode-only" alt="Pulsar dark logo">
  <img width="300" src="res/pulsar-logo-white.png#gh-dark-mode-only" alt="Pulsar light logo">

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

Pulsar is an event-driven framework for monitoring the activity of Linux devices at runtime, powered by [eBPF](https://ebpf.io/). 

The Pulsar core modules use eBPF probes to collect events from the kernel in a safe and efficient way. Pulsar events can be categorized in the four main following areas:

- **File I/O**: I/O operations on disk and memory.
- **Network**: data from the network stack.
- **Processes**: processes information, including file execution and file opening.
- **System Activity**: device activity, including system calls.

Pulsar is built with a modular design that makes it easy to adapt the core architecture to new use cases, create new modules or write custom rules.

## Quickstart

> **Warning**  
> A kernel 5.5 or higher with BPF and BTF enabled is required. Visit the official Pulsar website for the full [requirements](https://pulsar.sh/docs/faq/kernel-requirements/) and [installation options](https://pulsar.sh/docs/getting-started/installation) available.

To download and install Pulsar, run the following in your terminal:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/Exein-io/pulsar/main/pulsar-install.sh | sh
```

Launch the pulsar daemon in a terminal **with administrator privileges**:

```sh
pulsard
```

That's pretty much it. At this point Pulsar is actively monitoring the activity of all the target processes, and checking it against the set of security policies defined in the rules file. You can test this by triggering a threat event, for example running the following command in another terminal:

```sh
ln -s /etc/shadow /tmp/secret
```

In the pulsar terminal you should see something similar to:

```console
Event { header: Header { pid: 498, is_threat: true, source: ModuleName("rules-engine"), timestamp: SystemTime { tv_sec: 1667920537, tv_nsec: 113401482 }, image: "/usr/bin/ln", parent: 487, fork_time: SystemTime { tv_sec: 1667920537, tv_nsec: 102790045 } }, payload: RuleEngineDetection { rule_name: "Create sensitive files symlink", payload: FileLink { source: "/tmp/secret", destination: "/etc/shadow", hard_link: false } } }
```

As you can see from the `is_threat` field set to `true`, Pulsar is correctly identifying the symbolic link creation as a threat event.

### How does it work?

Behind the scenes, when an application performs an operation, it gets intercepted at kernel level by the Pulsar BPF probes, turned into a unique event object and sent to the userspace. There, the Pulsar rule engine processes the event against the set of rules defined in the rules file and, if there is a match, it emits a new event, marked as a threat. Finally a logger module prints threat events to the terminal.

In the example above, the event produced matched the following rule:

```yaml
- name: Read sensitive file
  type: FileOpened
  condition: (payload.filename IN ["/etc/shadow", "/etc/sudoers", "/etc/pam.conf", "/etc/security/pwquality.conf"] OR payload.filename STARTS_WITH "/etc/sudoers.d/" OR payload.filename STARTS_WITH "/etc/pam.d/") AND (payload.flags CONTAINS "O_RDONLY" OR payload.flags CONTAINS "O_RDWR")
```

## Installation

### (Recommended) Using the official installation script

The recommended approach to getting started with Pulsar is by using the official installations script. Follow the guide in the [Quickstart](#quickstart) section.

### Use Pre-built Binaries

Another approach to install Pulsar is by using a pre-built binary. Binaries are available for the [latest release](https://github.com/Exein-io/pulsar/releases/latest). Use `pulsar-exec` for x86-64 (`pulsar-exec-static` for a static build) or `pulsar-exec-static-aarch64` for AArch64 platform. Using there approach you also need to download and setup the [helper scripts](./scripts) to have a more convenient way to start in daemon/cli mode.

### Build from source

We do not recommend build Pulsar from source. Building from source is only necessary if you wish to make modifications. If you want to play with the source code check the [Developers](https://pulsar.sh/docs/category/developers) section of the documentation.

## Resources

- [Read the docs](https://pulsar.sh/docs): understand how to install and set up Pulsar.
- [Concepts](https://pulsar.sh/docs/category/concepts): dive deep into Pulsar architecture and main concepts.
- [Tutorials](https://pulsar.sh/docs/category/tutorials): learn how to use Pulsar with practical examples.
- [Develop new eBPF modules](https://pulsar.sh/docs/developers/tutorials/create-ebpf-probe-module): build new eBPF probes and integrate them into Pulsar through the modules system;
- [Roadmap](https://github.com/orgs/Exein-io/projects/14): check out the plan for next Pulsar releases;
- [Support](https://discord.gg/MQgaTPef7a): join the Discord server for community support.

## Contributing

If you're interested in contributing to Pulsar — thank you!

We have a [contributing guide](CONTRIBUTING.md) which will help you getting involved in the project. Also check the [Developers](https://pulsar.sh/docs/category/developers) section of the documentation for more information on Pulsar development.

## Community

Join the Pulsar [Discord server](https://discord.gg/MQgaTPef7a) to chat with developers, maintainers, and the whole community. You can also drop any question about Pulsar on the official [GitHub discussions](https://github.com/Exein-io/pulsar/discussions) or use the [GitHub issues](https://github.com/Exein-io/pulsar/issues) for feature requests and bug reports.

## License

Pulsar is [licensed](./LICENSE) under two licenses — Pulsar userspace code is licensed under [APACHE-2.0](./LICENSES/LICENSE-APACHE-2.0). Pulsar eBPF probes are licensed under [GPL-2.0](./LICENSES/LICENSE-GPL-2.0).
