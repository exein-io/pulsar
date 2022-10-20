# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
