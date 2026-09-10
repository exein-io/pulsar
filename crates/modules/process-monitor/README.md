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
|`pid_targets`|array of pids|List of PIDs to track|
|`pid_targets_children`|array of pids|List of PIDs to track (extended to children)|
|`targets`|array of images|List of processes to track|
|`targets_children`|array of images|List of processes to track (extended to children)|
|`whitelist`|array of images|List of processes to ignore|
|`whitelist_children`|array of images|List of processes to ignore (extended to children)|
|`track_by_default`|bool|Tracking status of PID 1 and of processes matching no rule|
|`ignore_self`|bool|Add the Pulsar executable to whitelist_children|

Default configuration:

```toml
[module.process-monitor]
enabled = true
pid_targets = []
pid_targets_children = []
targets = []
targets_children = []
whitelist = []
whitelist_children = []
track_by_default = true
ignore_self = true
```

For example, to limit Pulsar analysis to SSH connections:

```toml
[module.process-monitor]
whitelist_children = ["/usr/lib/systemd/systemd"]
targets_children = ["/usr/sbin/sshd"]
```

## Testing
You can try this module using this [example](../../../examples/standalone-probes/main.rs):

```sh
cargo xtask probe process-monitor
```
