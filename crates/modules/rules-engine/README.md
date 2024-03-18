# Rules Engine

This module will check every Pulsar event against the configured set of rules.
When a match is found, a threat event is generated.

## Rules

Default rules folder is `/var/lib/pulsar/rules`. Each rule file is a `yaml` file containing a list of rules with the following required fields:

- `name`: a unique name for identifying the rule
- `type`: the type of event to match (e.g. `FileOpened`, `Exec`, `NetworkConnection`)
- `description`: a human-readable description of the rule
- `severity`: the event severity (e.g. `low`, `medium`, `high`, `critical`)
- `category`: the threat category following the [MITRE ATT&CK](https://attack.mitre.org/) framework (e.g. `persistence`, `credential_access`, `defense_evasion`)
- `condition`: a condition to match the event.

Valid `severity` values are `low`, `medium`, `high`, and `critical`. 

Valid `category` values are (use `generic` if the rule does not fit any of the following):
`command_and_control`, `credential_access`, `defense_evasion`, `discovery`, `execution`, `exfiltration`, `impact`, `initial_access`, `lateral_movement`, `persistence`, `privilege_escalation`, `reconnaissance`, `resource_development`.

### Examples

Create a `/var/lib/pulsar/rules/example_rules1.yaml` with the following content:


```yaml
- name: Read sensitive file from untrusted process
  type: FileOpened
  condition: header.image != "/usr/bin/sshd" && payload.filename == "/etc/shadow"
  severity: high  
  category: generic
  description: A process different from sshd opened /etc/shadow which is a sensitive file
    that may contain hashed passwords.


- name: Executed telnet or nc
  type: Exec
  condition: payload.filename == "/usr/bin/telnet" || payload.filename == "/usr/bin/nc"
  severity: high
  category: generic
  description: The telnet and nc commands are often used by attackers to open reverse
    shells or to transfer files.
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
