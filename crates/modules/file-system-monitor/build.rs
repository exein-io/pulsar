fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_common::builder::build("probe.bpf.c")
}
