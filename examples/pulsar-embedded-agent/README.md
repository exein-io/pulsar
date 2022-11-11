# Embedding Pulsar in another application

This example shows how to use Pulsar as an inner component of another
application.

We develop a [custom module](./src/proxy_module.rs) and start pulsard like in the
[module example](../pulsar-extension-module), but this time we extract the
`ModuleContext` needed to [control the agent](./src/main.rs).
