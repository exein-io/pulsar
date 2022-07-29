# File System Monitor

This module watches the file system by adding eBPF hooks to LSM functions
(`security_inode_create`, `security_inode_unlink` and `security_file_open`)
and produces these events:

- `FileCreated`: `timestamp`, `pid`, `filename`
- `FileDeleted`: `timestamp`, `pid`, `filename`
- `FileOpened`: `timestamp`, `pid`, `filename`, `flags`
- `ElfOpened`: `timestamp`, `pid`, `filename`, `flags`

The elf checking feature is used to identify binaries and is implemented by
opening every accessed file and checking the presence of the ELF magic value
in its first bytes.

## Configuration

|Config|Type|Description|
|------|----|-----------|
|`elf_check_enabled`|boolean|Enable ELF check|
|`elf_check_whitelist`|path list|Paths ignored by ELF check|

Default configuration:

```ini
[file-system-monitor]
enabled=true
elf_check_enabled=true
elf_check_whitelist=/proc,/sys,/dev
```

You disable this module or the ELF check with:

```sh
pulsar config --set file-system-monitor.enabled=false
pulsar config --set file-system-monitor.elf_check_enabled=false
```

## Testing

You can try this module using the [probe binary](../../pulsar/bin/probe.rs):

```sh
cargo xtask probe file-system-monitor
```
