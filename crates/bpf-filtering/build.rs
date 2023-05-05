fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_builder::build("filtering_example", "src/filtering_example.bpf.c")
}
