fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("test_lsm", "src/test_lsm.bpf.c")
}
