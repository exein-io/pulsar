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
> A kernel 5.5 or higher with BPF and BTF enabled is required. Visit the official Pulsar website for the full [requirements](https://pulsar.sh/docs/requirements) and [installation options](https://pulsar.sh/docs/installation) available.

To download, install and run Pulsar, run the following in your terminal.

```sh
# Run the installer
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/Exein-io/pulsar/main/pulsar-install.sh | sh

# Launch the pulsar daemon
sudo pulsard
```

TODO - here we want a quick tour of Pulsar, including:
- showing events being monitored
- simple rule example
- simple detection example
- very simple step-by-step explanation of what is going on

## Resources

- [Read the docs](https://pulsar.sh/docs): understand how to install and set up Pulsar.
- [Concepts](https://pulsar.sh/docs/concepts): dive deep into Pulsar architecture and main concepts.
- [Tutorials](https://pulsar.sh/docs/tutorial): learn how to use Pulsar with practical examples.
- [Develop new modules](https://github.com/Exein-io/pulsar/blob/main/bpf-common/ProbeTutorial.md): build new eBPF probes and integrate them into Pulsar through the modules system;
- [Roadmap](https://github.com/Exein-io/projects/6): check out the plan for next Pulsar releases;
- [Support](https://discord.gg/MQgaTPef7a): join the Discord server for community support.


## Contributing

If you're interested in contributing to Pulsar — thank you!

We have a [contributing guide](CONTRIBUTING.md) which will help you getting involved in the project.

## Community

Join the Pulsar [Discord server](https://discord.gg/MQgaTPef7a) to chat with developers, maintainers, and the whole community. You can also drop any question about Pulsar on the official [GitHub discussions](https://github.com/Exein-io/pulsar/discussions) or use the [GitHub issues](https://github.com/Exein-io/pulsar/issues) for feature requests and bug reports.

## License

Pulsar is [licensed](./LICENSE) under two licenses — Pulsar userspace code is licensed under [APACHE-2.0](./LICENSES/LICENSE-APACHE-2.0). Pulsar eBPF probes are licensed under [GPL-2.0](./LICENSES/LICENSE-GPL-2.0).
