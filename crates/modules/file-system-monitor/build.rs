fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("probe.bpf.c")
}
