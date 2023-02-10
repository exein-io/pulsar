fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("src/feature_autodetect/test_lsm.bpf.c")
}
