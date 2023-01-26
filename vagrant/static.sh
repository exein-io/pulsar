
#!/usr/bin/env sh

# Run this from the repository root folder

# Make sure the correct target is installed.
# sudo apt-get install musl-tools
# rustup target add x86_64-unknown-linux-musl

set -e

features="--no-default-features --features core"
excluded="--exclude threat-response-lua"


export CARGO_BUILD_TARGET=x86_64-unknown-linux-musl
cargo build --bin pulsar-exec ${features}
cargo build --package test-suite

for vagrantfile in vagrant/*/Vagrantfile
do
  box=$(dirname $vagrantfile)
  cp "./target/${CARGO_BUILD_TARGET}/debug/pulsar-exec" "${box}/"
  cp "./target/${CARGO_BUILD_TARGET}/debug/test-suite" "${box}/"
done

