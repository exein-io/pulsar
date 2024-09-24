# Threat logger

This module will log Pulsar threat events to stdout.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|console|bool|log to stdout|
|syslog|bool|log to syslog|
|output_format|string|output format for events (plaintext, json)|

Default configuration:

```ini
[threat-logger]
enabled=true
console=true
syslog=true
output_format=plaintext
```

You disable this module with:

```sh
pulsar config --set threat-logger.enabled=false
```
