fn main() -> Result<(), Box<dyn std::error::Error>> {
    ebpf_builder::build("probes", "probes.bpf.c")
}
