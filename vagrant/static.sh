
#!/usr/bin/env sh

# Run this from the repository root folder

set -e

features="--no-default-features --features core"

export CARGO_BUILD_TARGET=x86_64-unknown-linux-musl
cross build --bin pulsar-exec ${features}
cross build --package test-suite

for vagrantfile in vagrant/*/Vagrantfile
do
  box=$(dirname $vagrantfile)
  cp "./target/${CARGO_BUILD_TARGET}/debug/pulsar-exec" "${box}/"
  cp "./target/${CARGO_BUILD_TARGET}/debug/test-suite" "${box}/"
done

