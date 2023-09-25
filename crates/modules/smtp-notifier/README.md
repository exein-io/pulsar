# Smtp notifier

This module will send an email notification when Pulsar identifies a threat.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`username` (required)|string|user credential for smtp server. Usually it's your email address, otherwise `sender` field must be set|
|`password` (required)|string|password credential for smtp server|
|`server` (required)|string|smtp server url to use|
|`receivers` (required)|string|comma separated emails to send notifications to|
|`port`|int|port for smtp server|
|`encryption`|string|encryption type to use for smtp: tls, starttls, none|
|`sender`|string|set this if `username` is not your email address or if you want a custom sender (custom sender address must be allowed by your email provider)|

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
