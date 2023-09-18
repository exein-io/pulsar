# Smtp notifier

This module will send an email notification when Pulsar identifies a threat.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`user` (required)|string|user credential for smtp server|
|`password` (required)|string|password credential for smtp server|
|`server` (required)|string|smtp server url to use|
|`receivers` (required)|string|comma separated emails to send notifications to|
|`port`|int|port for smtp server|
|`encryption`|string|encryption type to use for smtp: tls, starttls, none|
|`sender`|string|set a different email sender (should be allowed by email provider)|

Default configuration:

```ini
[smtp-notifier]
enabled=true
port=465
encryption=tls
```

You can disable this module with:

```sh
pulsar config --set smtp-notifier.enabled=false
```
