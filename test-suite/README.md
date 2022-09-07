# eBPF test suite

This binary loads the test suite exported by each module and executes it. 

Under the hood, we use [libtest-mimic](https://github.com/LukasKalbertodt/libtest-mimic)
to simulate a `cargo test`-like experience. For example, you can filter what
tests to run like this:

```
cargo xtask test open_file
```

We decided to make a separate executable (instead of using Rust tests) because
these eBPF integration tests require root privileges.


## Example

Every module should define its own test suite by using the APIs in
[bpf-common](../bpf-common/src/test_runner.rs), for example:

```rust
#[cfg(feature = "test-suite")]
pub mod test_suite {
    use bpf_common::{
        event_check,
        test_runner::{TestCase, TestRunner, TestSuite},
    };

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "file-system-monitor",
            tests: vec![open_file()],
        }
    }

    fn file_name() -> TestCase {
        TestCase::new("file_name", async {
            let path = std::env::temp_dir().join("file_name_1");
            TestRunner::with_ebpf(program)
                .run(|| { std::fs::File::create(&path); } )
                .await
                .expect_event(event_check!(
                    FsEvent::FileCreated,
                    (filename, path.to_str().unwrap().into(), "filename")
                ))
                .report()
        })
    }
}
```

The module must also be added the [test-suite main file](./src/main.rs):
```rust
// List of modules we want to test
let modules = [
    file_system_monitor::test_suite::tests(),
    network_monitor::test_suite::tests(),
    process_monitor::test_suite::tests(),
    syscall_monitor::test_suite::tests(),
];
```
