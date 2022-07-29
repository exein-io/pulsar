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
