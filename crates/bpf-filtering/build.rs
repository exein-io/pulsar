fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("task_reader", "src/ebpf/task_reader.bpf.c")?;

    #[cfg(feature = "test-suite")]
    bpf_builder::build("test_filtering", "src/ebpf/test_filtering.bpf.c")?;

    Ok(())
}
