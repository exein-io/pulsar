# Extending Pulsar with custom modules

This example shows how to extend Pulsar with a custom module.

```
$ cargo build && sudo ./target/debug/pulsar-extension-module pulsard
```

By default our custom module will do nothing, but we can instruct it to warn
about DNS queries to `exein.io`.
```
pulsar config --set my-custom-module.forbidden_dns=exein.io
dig exein.io
```

The commands above will produce this output in the Pulsar daemon:
```
Configuration changed: MyModuleConfig { print_events: false, forbidden_dns: Some("exein.io") }
Event { header: Header { pid: 28745, is_threat: true, source: ModuleName("network-monitor"), timestamp: SystemTime { tv_sec: 1668160509, tv_ns
ec: 818640866 }, image: "/usr/bin/dig", parent: 24586, fork_time: SystemTime { tv_sec: 1668160509, tv_nsec: 813495081 } }, payload: AnomalyDet
ection { score: 1.0 } }
```

## How to do it

The trick here is that we're building a new binary which includes our module on
top of Pulsar. By reusing crates, we can do just that with very few lines of code.

We'll add a dependency on the main Pulsar binary and launch it with the custom
module we wrote.

```
pulsar = { git = "https://github.com/Exein-io/pulsar", rev = "797f68641ed92b35b152e0d147b9cdcf3bfa49e5" }
pulsar-core = { git = "https://github.com/Exein-io/pulsar", rev = "797f68641ed92b35b152e0d147b9cdcf3bfa49e5" }
tokio = { version = "1", features = ["full"] }
```

Check the [main file](./src/main.rs) and the [custom module](./src/my_custom_module.rs) we're using in this example.
