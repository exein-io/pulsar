fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("test_lsm", "src/feature_autodetect/test_lsm.bpf.c")
}
