# Pulsar extension examples

This directory illustrates the various ways for extending Pulsar or re-using its
code.

The best way to extend Pulsar is [by adding new modules](./pulsar-extension-module).
These can be contributed back to the project as a pull request, or kept in
private repositories.
This is the best solution for:
- Extracting new events from the kernel
- Inspecting existing events and identifying security threats
- Sending these events to a remote server

If you want to re-use Pulsar eBPF hooks for augmenting your application with kernel observability,
you can simply [import that module as a crate](./pulsar-module-as-library).

Finally, for some very specific use-cases, it might make sense to run the agent
and controlling it from your application. You can either:
- run it as an external binary and control it with the `pulsar` CLI tool
- [embed it inside your application](./pulsar-embedded-agent) and control it
  with a `struct ModuleContext`.
