# Desktop notifier

This module will send a desktop notification when Pulsar identifies a threat.

Desktop notifications are handled by desktop environments following an XDG specification.
These messages are sent over the dbus session bus and the owner of the sender process
must match the user running the desktop environment. Since Pulsar runs as root, we'll
spawn a child `notify-send` subprocess with the configured user id.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`user_id`|int|Id of the user running the target desktop environment|
|`display`|string|Target display|
|`notify_send_executable`|string|executable for sending notifications|
|`bus_address`|string|address of the target session-bus|

The default configuration is compatible with Ubuntu.
To make sure your system is compatible, check the output of `id -u`,
`echo $DISPLAY` and `echo $DBUS_SESSION_BUS_ADDRESS`. Also, make sure
`notify-send` is installed.

```ini
[desktop-notifier]
enabled=false
user_id=1000
display=:0
notify_send_executable=notify-send
bus_address=unix:path=/run/user/1000/bus
```

This module is disabled by default. You can enable it with:

```sh
pulsar config --set desktop-notifier.enabled=true
```
