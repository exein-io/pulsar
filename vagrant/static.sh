
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

# build all tests and get file list
# https://github.com/rust-lang/cargo/issues/1924
tests=$(cargo test --no-run --message-format=json ${features} --workspace ${excluded}| jq -r .executable? | grep deps)

for vagrantfile in vagrant/*/Vagrantfile
do
  box=$(dirname $vagrantfile)
  cp "./target/${CARGO_BUILD_TARGET}/debug/pulsar-exec" "${box}/"
  test_folder="${box}/tests/"
  rm -rf "${test_folder}"
  mkdir "${test_folder}"
  cp ${tests} "${test_folder}"
done

