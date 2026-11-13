# Architecture

This is a prototype of a new architecture for Pulsar. It lives in `next/`, next to the current code, and doesn't change anything outside of it. The daemon is `pulsard-next`.

Today every module gets every event from a bus and keeps its own state. The prototype replaces the bus with one pipeline:

```text
probes ─▶ ring buffer ─▶ ingest task ─▶ processor task ─▶ reporter tasks
                                        decode, process table, detectors
```

## Main ideas

1. Every probe, including probes of extensions, writes into one pinned BPF ring buffer, so userspace reads all records in a single order. Records that can't be written are counted in the kernel, and every record carries that counter. This way userspace knows exactly where records are missing.
2. Records are defined once, in plain C headers (`bpf/include/pulsar/abi.h`). Each record starts with a header: producer, kind, size, timestamp and the process it is about. Rust types are generated from the headers with bindgen, and records are decoded without unsafe code. A record is identified by (producer, kind) tuple. Producer ids are assigned when objects are loaded, so there is no global registry of kinds.
3. A single processor task decodes records, keeps the process table, runs detectors and builds threats. Detectors must not block. Reporters receive only threats, each on its own task. A slow reporter loses its oldest threats instead of slowing down the processor.
4. Values that are unknown stay unknown. A field a probe couldn't read, or one that depends on lost records, is `None`, never an empty string or 0. A rule condition on an unknown value is false. The rules engine adds the `Some` steps itself, so the shipped rules didn't change.
5. Extensions are types, not plugins. A build chooses a `Schema`: payload and threat kind enums composed by macros from the OSS variants and its own. Probes, detectors and reporters are generic over it, and rules can match extension payloads. `extension-example` shows how pulsar-enterprise would use this: its probe writes into the shared ring, and it adds its own payload, rule, detector and reporter, using only public APIs.
6. No record is lost at start. The ring is read before any probe is attached, process probes are attached before `/proc` is read, and all other probes after that.

Details are in the code. Good starting points are `core/src/lib.rs` and `bpf/include/pulsar/abi.h`.

## Crates

- `bpf-builder`: compiles probes and generates Rust types from ABI headers. Extensions use it too.
- `bpf`: all kernel code, the C SDK in `include/pulsar/`, the loader and the ring reader.
- `core`: events, payloads, threats, the process table, the processor and the builder.
- `rules-engine`, `reporters/threat-logger`: copies of the current crates, adapted.
- `pulsard`: the `pulsard-next` binary and its configuration.
- `extension-example`: a stand-in for pulsar-enterprise, with the `pulsard-example` binary.

## Not done

Not all modules were ported, as I wanted to have minimal working structure showcasing the new architecture.

- File and network probes, and with them attributing network events to the socket owner (#418).
- Desktop and SMTP notifiers, the HTTP API and container details.
- Checks on kernel 5.10 and with clang 18.
- Seeding the interest map at start has a gap for processes forked meanwhile.

## Open questions

- Should event windows and lineage be part of open pulsar, or should they only exist in EE? This draft shows how the former version could look like.
- Currently `header.container` being `None` can mean either that process is not in a container, or that we failed to get this information. Should we distinguish those two states (have something like `Option<Option<Container>>`)?
- C header files are passed to downstream crates using cargo build system (see `extension-example/build.rs` and its usage of `DEP_BPF_ABI_INCLUDE` env variable). Is it ok? Or should they be vendored by EE?
