# Network Monitor

This module watches for network events:

- `Bind`: `timestamp`, `pid`, `address`
- `Connect`: `timestamp`, `pid`, `source`, `destination`
- `Accept`: `timestamp`, `pid`, `source`, `destination`
- `Send`: `timestamp`, `pid`, `source`, `destination`, `len`, `is_tcp`
- `Receive`: `timestamp`, `pid`, `source`, `destination`, `len`, `is_tcp`
- `Close`: `timestamp`, `pid`, `source`, `destination`

This module also contains a DNS interceptor which will try to parse every UDP message:

- `DnsQuery`: `timestamp`, `pid`, `questions`
- `DnsAnswer`: `timestamp`, `pid`, `questions`, `answers`


## Configuration

|Config|Type|Description|
|------|----|-----------|
|-|-|-|

Default configuration:

```ini
[network-monitor]
enabled=true
```

You disable this module with:

```sh
pulsar config --set network-monitor.enabled=false
```

## Testing
You can try this module using this [example](../../../examples/standalone-probes/main.rs):

```sh
cargo xtask probe network-monitor
```
