use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let include = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include");
    println!("cargo::metadata=include={}", include.display());

    next_bpf_builder::build("process", "probes/process.bpf.c", &[&include])?;
    next_bpf_builder::embed("process")?;

    next_bpf_builder::generate_abi(
        "pulsar",
        &[
            "pulsar/abi.h",
            "pulsar/abi/process.h",
            "pulsar/abi/file.h",
            "pulsar/abi/network.h",
        ],
        &[&include],
        "abi.rs",
    )
}
