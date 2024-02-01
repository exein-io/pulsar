# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
-

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
