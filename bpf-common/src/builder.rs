use std::{env, path::PathBuf, process::Command, string::String};

use anyhow::Context;

static CLANG_DEFAULT: &str = "clang";
static LLVM_STRIP: &str = "llvm-strip";
static INCLUDE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/include");

pub fn build(probe: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed={probe}");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/common.bpf.h");
    println!("cargo:rerun-if-changed={INCLUDE_PATH}/buffer.bpf.h");

    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    let out_object = out_path.join("probe.bpf.o");

    let clang = match env::var("CLANG") {
        Ok(val) => val,
        Err(_) => String::from(CLANG_DEFAULT),
    };

    // Compile
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let include_path = PathBuf::from(INCLUDE_PATH);
    let status = Command::new(clang)
        .arg(format!("-I{}", include_path.to_string_lossy()))
        .arg(format!("-I{}", include_path.join(&arch).to_string_lossy()))
        .arg("-g")
        .arg("-O2")
        .args(["-target", "bpf"])
        .arg("-c")
        .arg("-Werror")
        .arg(format!(
            "-D__TARGET_ARCH_{}",
            match arch.as_str() {
                "x86_64" => "x86".to_string(),
                "aarch64" => "arm64".to_string(),
                "riscv64" => "riscv".to_string(),
                _ => arch.clone(),
            }
        ))
        .arg(probe)
        .arg("-o")
        .arg(&out_object)
        .status()
        .context("Failed to execute clang")?;

    if !status.success() {
        Err("Failed to compile eBPF program")?;
    }

    // Strip debug symbols
    let status = Command::new(LLVM_STRIP)
        .arg("-g")
        .arg(out_object)
        .status()
        .context("Failed to execute llvm-strip")?;

    if !status.success() {
        Err("Failed strip eBPF program")?;
    }

    Ok(())
}
