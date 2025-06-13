# Cross containers

These containers are used in conjunction with [cross](https://github.com/cross-rs/cross) to build Pulsar in a reproducible way without worrying about system dependencies.

Containers are based on the default [cross containers](https://github.com/orgs/cross-rs/packages) built from `Ubuntu 20.04 LTS`, with the addition of:

-   `Clang/LLVM 20`
-   `libssl-dev` speficic for the target architecture, example `libssl-dev:arm64`
-   `libsqlite3-dev` speficic for the target architecture, example `libsqlite3-dev:arm64`
