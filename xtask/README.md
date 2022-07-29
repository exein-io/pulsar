# XTasks

This crate contains tasks automation for pulsar development.
See [cargo-xtask](https://github.com/matklad/cargo-xtask) for documentation on how this works.

The main reason we have added these wrappers is that we require root priviledges
to load eBPF code. These tasks will build the binaries normally and execute them
with `sudo`.

## Run test suite

To run the eBPF test suite you can use:
```sh
cargo xtask test
```

## Run pulsar daemon

To run the agent daemon you can use:
```sh
cargo xtask pulsard
```

## Run pulsar client

To run the agent client you can use:
```sh
cargo xtask pulsar
```

## Run single probe

To run a single module you can use:
```sh
cargo xtask probe file-system-monitor
```
