//! Integration tests of the prototype: real probes and real processes, checked
//! on the events the processor produces.
//!
//! Loading the probes needs root, so run it as root or in a VM (`vm.sh`).

mod process;

use std::process::ExitCode;

fn main() -> ExitCode {
    next_test_suite_harness::run(process::tests)
}
