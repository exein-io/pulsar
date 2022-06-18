fn main() -> Result<(), Box<dyn std::error::Error>> {
    bpf_common::builder::build("on_sys_enter.bpf.c")
}
