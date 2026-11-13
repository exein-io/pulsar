use std::{env, path::PathBuf};

fn main() -> anyhow::Result<()> {
    let include = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include");
    // Pulsar's ABI and SDK headers, from next-bpf (`links = "bpf-abi"`).
    let pulsar = PathBuf::from(env::var("DEP_BPF_ABI_INCLUDE")?);

    next_bpf_builder::build("syscalls", "probes/syscalls.bpf.c", &[&include, &pulsar])?;
    next_bpf_builder::embed("syscalls")?;

    next_bpf_builder::generate_abi(
        "example",
        &["example/abi.h"],
        &[&include, &pulsar],
        "abi.rs",
    )
}
