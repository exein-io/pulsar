# Smtp notifier

This module will send an email notification when Pulsar identifies a threat.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`username` (required)|string|user credential for smtp server. Usually it's your email address, otherwise `sender` field must be set|
|`password` (required)|string|password credential for smtp server|
|`server` (required)|string|smtp server url to use|
|`receivers` (required)|array of strings|emails to send notifications to|
|`port`|int|port for smtp server|
|`encryption`|string|encryption type to use for smtp: tls, starttls, none|
|`sender`|string|set this if `username` is not your email address or if you want a custom sender (custom sender address must be allowed by your email provider)|

Default configuration:

```toml
[module.smtp-notifier]
enabled = false
port = 465
encryption = "tls"
```

This module is disabled by default. Enable it in `/var/lib/pulsar/pulsar.toml`,
filling in the required fields, then restart the daemon:

```toml
[module.smtp-notifier]
enabled = true
server = "smtp.example.com"
username = "pulsar@example.com"
password = "secret"
receivers = ["admin@example.com"]
```
