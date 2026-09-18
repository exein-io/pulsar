# Threat logger

This module will log Pulsar threat events to stdout.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|console|bool|log to stdout|
|syslog|bool|log to syslog|
|output_format|string|output format for events (plaintext, json)|

Default configuration:

```toml
[module.threat-logger]
enabled = true
console = true
syslog = true
output_format = "plaintext"
```

You disable this module in `/var/lib/pulsar/pulsar.toml`, then restart the
daemon:

```toml
[module.threat-logger]
enabled = false
```
