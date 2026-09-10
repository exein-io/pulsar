# Rules Engine

This module will check every Pulsar event against the configured set of rules.
When a match is found, a threat event is generated.

## Rules

Default rules folder is `/var/lib/pulsar/rules`, searched recursively: every `toml` file below it is loaded as a rule file. Each file holds an array of tables under the `rules` key, where every rule has the following required fields:

- `name`: a unique name for identifying the rule
- `type`: the type of event to match (e.g. `FileOpened`, `Exec`, `NetworkConnection`)
- `description`: a human-readable description of the rule
- `severity`: the event severity (e.g. `low`, `medium`, `high`, `critical`)
- `category`: the threat category following the [MITRE ATT&CK](https://attack.mitre.org/) framework (e.g. `persistence`, `credential_access`, `defense_evasion`)
- `condition`: a condition to match the event.

Valid `severity` values are `low`, `medium`, `high`, and `critical`. 

Valid `category` values are (use `generic` if the rule does not fit any of the following):
`command_and_control`, `credential_access`, `defense_evasion`, `discovery`, `execution`, `exfiltration`, `impact`, `initial_access`, `lateral_movement`, `persistence`, `privilege_escalation`, `reconnaissance`, `resource_development`.

Conditions are written as TOML literal strings, in single quotes, so the double
quotes they contain need no escaping. Use `'''` for a condition spanning several
lines.

### Examples

Create a `/var/lib/pulsar/rules/example_rules1.toml` with the following content:

```toml
[[rules]]
name = "Read sensitive file from untrusted process"
type = "FileOpened"
severity = "high"
category = "generic"
description = "A process different from sshd opened /etc/shadow which is a sensitive file that may contain hashed passwords."
condition = 'header.image != "/usr/bin/sshd" AND payload.filename == "/etc/shadow"'

[[rules]]
name = "Executed telnet or nc"
type = "Exec"
severity = "high"
category = "generic"
description = "The telnet and nc commands are often used by attackers to open reverse shells or to transfer files."
condition = 'payload.filename == "/usr/bin/telnet" OR payload.filename == "/usr/bin/nc"'
```

The first rule will cause a warning whenever a process different from `sshd` opens
`/etc/shadow`. The second rule will warn when `telnet` or `nc` are run.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|rules_path|path|Folder containing the `toml` rules|


Default configuration:

```toml
[module.rules-engine]
enabled = true
rules_path = "/var/lib/pulsar/rules"
```

You disable this module in `/var/lib/pulsar/pulsar.toml`, then restart the
daemon:

```toml
[module.rules-engine]
enabled = false
```
