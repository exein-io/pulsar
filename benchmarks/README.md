# Pulsar Benchmarks

This folder contains benchmarks related to Pulsar.

## Bus implementation benchmarks

[The bus benchmarks](./benches/bus.rs) contain several possibile Bus implementations.

```
bus/argo                time:   [175.90 ms 177.28 ms 178.82 ms]
bus/crossbeam_dispacher time:   [8.0496 ms 8.1400 ms 8.2391 ms]
bus/crossbeam_mutex     time:   [9.6050 ms 9.7174 ms 9.8822 ms]
bus/jonhoo              time:   [5.7250 ms 5.8237 ms 5.9113 ms]
bus/tokio               time:   [22.981 ms 24.418 ms 25.016 ms]
```

# Ideas for further tests

Users will want to now how slower the system will run with Pulsar enabled.
- Test inside a virtual machine or an embedded system with limited resources.
- Measure time from eBPF event to consumption point (latency)
- Measure CPU usage from eBPF event to consumption point (CPU usage)
- Measure When things starts to fail

We could make integration tests which trigger probes and use them for both
benchmarks and probe testing.

# Useful links

https://github.com/flamegraph-rs/flamegraph
https://github.com/bheisler/criterion.rs
