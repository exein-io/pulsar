# Rules Engine

This module will check every Pulsar event against the configured set of rules.
When a match is found, a threat event is generated.

## Example rule

Create a `/var/lib/pulsar/rules/example_rules1.yaml` with the following content:

```yaml
- name: Read sensitive file from untrusted process
  type: FileOpened
  condition: header.image != "/usr/bin/sshd" && payload.filename == "/etc/shadow"

- name: Executed telnet or nc
  type: Exec
  condition: payload.filename == "/usr/bin/telnet" || payload.filename == "/usr/bin/nc"
```

The first rule will cause a warning whenever a process different from `sshd` opens
`/etc/shadow`. The second rule will warn when `telnet` or `nc` are run.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|rules_path|path|Folder containing the `yaml` rules|


Default configuration:

```ini
[rules-engine]
enabled=true
rules_path=/var/lib/pulsar/rules
```

You disable this module with:

```sh
pulsar config --set rules-engine.enabled=false
```
