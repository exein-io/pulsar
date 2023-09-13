# Smtp notifier

This module will send an email notification when Pulsar identifies a threat.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`user`|string|user credential for smtp server|
|`password`|string|password credential for smtp server|
|`server`|string|smtp server url to use|
|`receiver`|string|email to send notifications to|
|`port`|int|port for smtp server|
|`encryption`|string|encryption type to use for smtp: tls, start-tls, plain|
|`set_from`|bool|set the from header to Pulsar <pulsar-threat-notification@gmail.com>|

```ini
[smtp-notifier]
enabled=true
user=youremail@gmail.com
password=<gmail app password>
server=smtp.gmail.com
receiver=receiver@gmail.com
port=465
encryption=tls
set_from=true
```

You can disable this module with:

```sh
pulsar config --set smtp-notifier.enabled=false
```
