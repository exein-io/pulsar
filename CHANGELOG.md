# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **BREAKING**: configuration format from INI to TOML, the file moved to `/var/lib/pulsar/pulsar.toml`
- **BREAKING**: module settings live under a `[module.<name>]` section and lists are TOML arrays instead of comma separated strings
- **BREAKING**: rules format from YAML to TOML, rule files hold an array of tables under a `rules` key and every `toml` file below the rules folder is loaded as one
- **BREAKING**: invalid values in the `[pulsar]` section are fatal instead of falling back to the default
- **BREAKING**: `output_format` of `threat-logger` is matched case sensitively, use `plaintext` or `json`
- **BREAKING**: module configurations are `serde::Deserialize` types instead of `TryFrom<&ModuleConfig>` implementors
- configuration is parsed once at startup, a broken section of an enabled module now stops the daemon instead of failing that module later
- unknown configuration keys and sections are reported as warnings instead of being ignored silently
- a missing configuration file is created from a commented template instead of an empty file
- the installer keeps an existing configuration file instead of overwriting it

### Added

- test loading and compiling every rule shipped with Pulsar

### Removed

- **BREAKING**: `pulsar config` command, together with the `/configs` and `/modules/{name}/config` API endpoints. Edit the configuration file and restart the daemon instead
- **BREAKING**: configuration reload at runtime, including the `on_config_change` module hook

## [0.10.0] - 2026-09-17

### Fixed

- network-monitor: validate the IPv4, ICMP and TCP header lengths before
  computing the payload length, preventing an integer underflow in `data_len`
  on crafted packets (#374)
- eBPF: fixed leaking per-cpu event slots for probe messages if probe returned
  early (#381)
- eBPF: zero every event field on creation, so an event can no longer expose
  leftover data from a previous event on the same cpu (#381)
- eBPF: fixed buffer_index len set in buffer_append_user_memory (#382)
- eBPF: handle the `struct kernfs_node` layout change of kernel 6.15, with the
  vendored `vmlinux.h` updated to 6.15.2 (#351)
- eBPF: `make_path` verifier error in `file-system-monitor` (#350)
- rule DSL: the `<=` operator was evaluated as `>=` (#348)
- daemon deadlock while starting a module (#342)
- daemon deadlock while waiting for the module `init_state` result (#364)
- missing dash in the `riscv64` architecture string in `pulsar-install.sh` (#346)
- ci: bundle `pulsar-install.sh` in tagged releases, not only in `dev` ones (#320)

### Added

- `btf_path` configuration option to load BTF from a file instead of the
  running kernel (#368)
- `pulsar --version` and `pulsard --version` report the git commit sha and the
  build profile alongside the version (#369)
- rules-engine: the matching rule `condition` is now part of the threat
  metadata (#372)
- new *Command and Control* rules (#355)
- new *Credential Access* rules (#356)
- regression tests for malformed network packets (#381)
- regression tests for buffer_append_user_memory behaviour (#382)
- ci: `riscv64gc-unknown-linux-musl` release build (#354)
- ci: run integration tests in virtual machines using `lvh` (#353)

### Changed

- **BREAKING**: the single `pulsar-exec` binary is split into `pulsard`
  (daemon) and `pulsar` (CLI), replacing the `scripts/pulsar` and
  `scripts/pulsard` wrappers (#369)
- **BREAKING**: `elf_check` in `file-system-monitor` now defaults to `false` (#349)
- **BREAKING**: modules read optional settings with `ModuleConfig::optional`,
  which returns an `Option`, instead of `ModuleConfig::with_default` (#349)
- **BREAKING**: the `engine-api` client returns the typed `EngineClientError`
  instead of `anyhow::Error` (#338)
- **BREAKING**: switch to the Rust 2024 edition, raising the minimum supported
  Rust version to 1.85 (#335)
- rules: `basic-rules.yaml` is split into per-tactic directories under `rules/` (#362)
- xtask: `surun` forwards signals to the child process (#363)
- update aya to 0.13.1 (#334)
- update vendored libbpf to v1.6.2 (#370)
- update axum and hyper (#322)
- use the aya kernel version implementation instead of the internal one (#323)
- ci: build the BPF probes with clang 20 (#324, #352)
- ci: pin the Rust toolchain in `rust-toolchain.toml` (#385)

### Removed

- **BREAKING**: `SyscallActivity` event type (#365)
- **BREAKING**: process filtering by raw cgroup definition, together with the
  `cgroup_targets` option and the `CgroupCreated`, `CgroupDeleted` and
  `CgroupAttach` events (#366)
- **BREAKING**: syscall number tables from `bpf-common::platform` (#325)

## [0.9.0] - 2024-11-15

### Fixed

- `path_rename` lsm hook for kernel >= 5.19
- **BREAKING**: threat logger module rename
- docker container ID parsing with cgroupfs driver
- **BREAKING**: `Event` display format removing additional line
- rules DSL quoted strings
- filtering test

### Added

- detect image layer directory for `podman`
- ci: integration test using [architest](https://github.com/exein-io/architest)
- ci: bundle the installer in the release
- syslog priority
- add `uid` and `gid` to event header and process map
- allow threats to be logged as JSON
- new metadata fields for the rules (`category`, `severity`, `description`)
- include `riscv64gc` in `pulsar-install.sh`

### Changed

- **BREAKING**: xtask: switch to `xtask surun` command to improve running as root in development
- **BREAKING**: use `elf_check` instead of `elf_check_enabled` in `file-system-monitor`
- **BREAKING**: new modules API, modules need to simply implement a trait
- ci: run workflows on all pull requests, not only the ones to `main` branch
- improved BPF features detection
- ci: use cross-rs even for native builds
- **BREAKING**: xtask: unify `test` and `cross` subcommands
- prefer rustls over OpenSSL for static builds

### Removed

- wrong telnet rule

## [0.8.1] - 2024-03-05

### Fixed

- `bpf_strncmp` compatibility for older kernel versions

## [0.8.0] - 2024-02-15

### Added

- MITRE compatible ruleset
- rule dsl: type methods
- rule dsl: unary conditions
- rule dsl: option field support

## [0.7.1] - 2024-02-01

### Added

- boltdb support for `podman` container configuration

### Changed

- read cgroup name in BPF

### Fixed

- one character string value in rule engine DSL
- handle containers which were running before Pulsar

## [0.7.0] - 2023-12-20

### Added

- support for monitoring containers within the core functionality
- new `description` field in the *Threat* structure, providing a human-readable description of the threat
- new `namespaces` field for events related to *fork* and *exec* operations
- SMTP integration within the module for logging threats to sent threats also via email
- ability to modules to display warnings as part of their functionality
- *syslog* capabilities to the logger module
- new `enabled_by_default` flag for every module, allowing the definition of default behavior
- CI: create release/dev containers on tags/main-updates

### Changed

- bpf: refactored preemption in the BPF probes
- CI: rewritten workflows because of deprecated actions
- move dependecnies in workspace
- bpf: clean probes license

### Fixed

- issue introduced by changes in the kernel affecting the layout of the `struct iov_iter` in `network-monitor` probe
- doctest in the `validation` module
- check the payload before applying the ruleset in the `rule-engine` module to correctly handle cases of rules only on the header
- bpf: disable stack protector on probes

## [0.6.0] - 2023-06-05

### Added

- cross compilation task
- bpf loop detection
- extract absolute file paths on exec
- cgroup support
- collection support in rules
- dynamic fields compare in rules

### Changed

- improved LSM autodetect
- allow more that one BPF program per module
- moved `get_path_str` to shared header
- more modular event filtering
- validatron rewrite

### Fixed

- uname parse for wsl2
- module manager start command
- memory alignments issue in bpf output event struct
- warning on stopping never started modules

## [0.5.0] - 2023-02-06

### Added

- better examples
- markdown link checker
- `desktop-notifier` module
- event monitor API endpoint
- `monitor` command on `pulsar` cli
- scripts to ease development
- support for kernel 6.x
- `LOOP` macro to handle loops with `bpf_loop` on supported kernels

### Changed

- improve test suite
- better daemon/logger module output format
- new threat event structure to support derived, custom, empty payloads
- send eBPF events in a more memory efficient way
- move pulsar to workspace root package

### Fixed

- sporadic segmentation fault when running test-suite
- track parent process changes
- module/crate version coherency
- startup warnings in ebpf programs

### Removed

- non core payloads from payload variants 

## [0.4.0] - 2022-10-26

### Added

- Basic rules
- argv in events

### Changed

- Installed download basic rules

### Fixed

- Cross containers
- FIleFlag checks and compare

## [0.3.0] - 2022-10-20

### Added

- Pulsar installer script
- Github release workflow
- Increase rlimit on daemon start
- More network events and fields
- More filesystem events and fields

### Changed

- Better quickstart on README 
- Strip debug symbols from BPF probes
- Proper error context in `bpf-common`
- Improved fields in `Payload` structure

### Fixed

- Delete correct unix socket
- Error handling in `ProcessTracker`

### Secuity

- update `axum` to address a cve

## [0.2.0] - 2022-09-13

### Added

- Initial support for Android
- Add Github workflows
- Add xtask commands (test, pulsard, pulsar, probe)

### Changed

- Replace Kprobes with LSM and tracepoints where possible
- Refactor test suite as external executable
