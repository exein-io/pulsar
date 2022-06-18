# Process Monitor

This module keeps track of the running processes by monitoring the scheduler
with eBPF. These events are produced:

- `Fork`: `timestamp`, `pid`, `ppid`
- `Exec`: `timestamp`, `pid`, `filename`
- `Exit`: `timestamp`, `pid`, `exit_code`

## Global process tracking

This module influences with its configuration what processes are tracked by Pulsar, including
all other modules.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`pid_targets`|pid list|List of PIDs to track|
|`pid_targets_children`|pid list|List of PIDs to track (extended to children)|
|`targets`|image list|List of processes to track|
|`targets_children`|image list|List of processes to track (extended to children)|
|`whitelist`|image list|List of processes to ignore|
|`whitelist_children`|image list|List of processes to ignore (extended to children)|

Default configuration:

```ini
[process-monitor]
enabled=true
pid_targets=
pid_targets_children=
targets=
targets_children=
whitelist=
whitelist_children=
```

For example, to limit Pulsar analisys to SSH connections with:

```sh
pulsar config --set process-monitor.whitelist_children=/usr/lib/systemd/systemd
pulsar config --set process-monitor.targets_children=/usr/sbin/sshd
```

## Testing

You can try this module using the [probe example](../../pulsar/examples/probe.rs):

```sh
cargo run --example probe -- process-monitor
```
