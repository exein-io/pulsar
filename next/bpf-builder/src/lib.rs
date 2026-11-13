use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    string::String,
};

use anyhow::{Context, bail};
use bindgen::callbacks::{DeriveInfo, ParseCallbacks, TypeKind};
use bpf_features::BpfFeatures;
use quote::quote;

static CLANG_DEFAULT: &str = "clang";
static LLVM_STRIP: &str = "llvm-strip";
// The vendored libbpf headers and vmlinux.h are used where they are, in the
// original bpf-builder crate.
static LIBBPF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/bpf-builder/include"
);
static VMLINUX_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/bpf-builder/vmlinux"
);

// Given a probe name and the eBPF program source code path, compile it to OUT_DIR.
// We'll build multiple versions with all combinations of eBPF features we rely
// on. Lack of certain feature will result in using legacy replacements.
// `include_dirs` come first on the include path, before libbpf and vmlinux.h.
pub fn build(name: &str, source: &str, include_dirs: &[&Path]) -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed={source}");
    for dir in include_dirs {
        println!("cargo:rerun-if-changed={}", dir.display());
    }
    println!("cargo:rerun-if-changed={LIBBPF_PATH}");
    println!("cargo:rerun-if-changed={VMLINUX_PATH}");

    let out_dir = env::var("OUT_DIR").context("OUT_DIR not set")?;
    let out_path = Path::new(&out_dir).join(name);

    for (_, (bpf_objfile_suffix, build_args)) in BpfFeatures::all_combinations() {
        let filename = format!("{name}.{bpf_objfile_suffix}");
        let full_path = out_path.with_file_name(filename);
        compile(source, full_path, include_dirs, &build_args)
            .with_context(|| format!("Error compiling programs with features: {build_args:?}"))?;
    }

    Ok(())
}

// Writes `OUT_DIR/<name>_objects.rs`: an array of `(BpfFeatures, &[u8])`, one
// entry per variant compiled by `build`. The includer needs `BpfFeatures` in
// scope and a dependency on aya.
pub fn embed(name: &str) -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR").context("OUT_DIR not set")?;
    let mut entries = Vec::new();
    for (features, (bpf_objfile_suffix, _)) in BpfFeatures::all_combinations() {
        let path = format!("{out_dir}/{name}.{bpf_objfile_suffix}");
        entries.push(quote! { (#features, aya::include_bytes_aligned!(#path)) });
    }
    let table = quote! { [#(#entries),*] };
    fs::write(
        Path::new(&out_dir).join(format!("{name}_objects.rs")),
        table.to_string(),
    )?;
    Ok(())
}

// Generates `OUT_DIR/<out>`: Rust types for the record definitions in
// `headers`, with zerocopy derives so records can be read from bytes without
// unsafe code. Only `<prefix>_*` types and `<PREFIX>_*` constants are kept.
//
// The `pulsar_*` types are generated only by next-bpf. An extension's types
// refer to them by name, so the extension includes its file where
// `next_bpf::abi::*` is in scope.
pub fn generate_abi(
    prefix: &str,
    headers: &[&str],
    include_dirs: &[&Path],
    out: &str,
) -> anyhow::Result<()> {
    let out_dir = env::var("OUT_DIR").context("OUT_DIR not set")?;
    let wrapper: String = headers
        .iter()
        .map(|h| format!("#include \"{h}\"\n"))
        .collect();
    let mut builder = bindgen::Builder::default();
    if prefix != "pulsar" {
        builder = builder.blocklist_type("pulsar_.*");
    }
    builder
        .header_contents("abi_wrapper.h", &wrapper)
        .clang_args(
            include_dirs
                .iter()
                .map(|dir| format!("-I{}", dir.display())),
        )
        .allowlist_type(format!("{prefix}_.*"))
        .allowlist_var(format!("{}_.*", prefix.to_uppercase()))
        .prepend_enum_name(false)
        .derive_default(true)
        .parse_callbacks(Box::new(ZerocopyDerives))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .context("Failed to generate the ABI types")?
        .write_to_file(Path::new(&out_dir).join(out))
        .context("Failed to write the ABI types")?;
    Ok(())
}

#[derive(Debug)]
struct ZerocopyDerives;

impl ParseCallbacks for ZerocopyDerives {
    fn add_derives(&self, info: &DeriveInfo<'_>) -> Vec<String> {
        match info.kind {
            TypeKind::Struct => ["FromBytes", "KnownLayout", "Immutable"]
                .iter()
                .map(|derive| format!("zerocopy::{derive}"))
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn compile(
    probe: &str,
    out_object: PathBuf,
    include_dirs: &[&Path],
    extra_args: &[String],
) -> anyhow::Result<()> {
    let clang = env::var("CLANG").unwrap_or_else(|_| String::from(CLANG_DEFAULT));
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let include_path = PathBuf::from(LIBBPF_PATH);
    let vmlinux_path = PathBuf::from(VMLINUX_PATH).join(&arch);

    // Fail loudly on an unsupported arch instead of passing an undefined
    // __TARGET_ARCH_* through, which would silently miscompile the BPF.
    let target_arch = match arch.as_str() {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        "riscv64" => "riscv",
        other => {
            bail!("unsupported target arch `{other}`: only x86_64, aarch64, riscv64 are supported")
        }
    };

    // Keep next/bpf/compile_flags.txt in sync with these flags.
    let status = Command::new(clang)
        .args(
            include_dirs
                .iter()
                .map(|dir| format!("-I{}", dir.display())),
        )
        .arg(format!("-I{}", include_path.to_string_lossy()))
        .arg(format!("-I{}", vmlinux_path.to_string_lossy()))
        .arg("-g")
        .arg("-O2")
        .args(["-target", "bpf"])
        .arg("-c")
        .arg("-Werror")
        .arg("-fno-stack-protector")
        // Explicitly pass ISA version, to not rely on clang defaults.
        .arg("-mcpu=v3")
        // Kernel >= 7.0 is built with -fms-extensions and vmlinux.h contains
        // anonymous members of named structs (`struct foo;`), which is a
        // Microsoft extension.
        .arg("-fms-extensions")
        .arg("-Wno-microsoft-anon-tag")
        .arg(format!("-D__TARGET_ARCH_{target_arch}"))
        .args(extra_args)
        .arg(probe)
        .arg("-o")
        .arg(&out_object)
        .status()
        .context("Failed to execute clang")?;

    if !status.success() {
        bail!("Failed to compile eBPF program");
    }

    // Strip debug symbols
    let status = Command::new(LLVM_STRIP)
        .arg("-g")
        .arg(out_object)
        .status()
        .context("Failed to execute llvm-strip")?;

    if !status.success() {
        bail!("Failed strip eBPF program");
    }

    Ok(())
}
