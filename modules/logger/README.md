# Logger

This module will log Pulsar threat events to stdout.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|console|bool|log to stdout|

Default configuration:

```ini
[logger]
enabled=true
console=true
```

You disable this module with:

```sh
pulsar config --set logger.enabled=false
```
