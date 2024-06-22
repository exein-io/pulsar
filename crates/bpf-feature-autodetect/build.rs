fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("test_bpf_loop", "src/test_bpf_loop.bpf.c")?;
    bpf_builder::build("test_lsm", "src/test_lsm.bpf.c")?;
    Ok(())
}
