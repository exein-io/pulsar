use std::{
    ffi::OsStr,
    fs::{self, File},
    io::prelude::*,
    os::unix::fs::symlink,
    path::PathBuf,
    process::{Command, Stdio},
};

use anyhow::Result;
use clap::Parser;
use serde::Deserialize;

use crate::tempdir::TempDir;

const REPO_URL: &str = "git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git";
const KERNEL_API: &str = "https://www.kernel.org/releases.json";

/// Type of C compiler used for the build.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CompilerType {
    Llvm,
    Gcc,
}

#[derive(Debug, Parser)]
pub(crate) struct Options {
    /// Compiler to use for the build.
    #[arg(long, default_value = "clang")]
    compiler: String,
    /// Type of C compiler used for the build.
    #[arg(long, value_enum, default_value_t = CompilerType::Llvm)]
    compiler_type: CompilerType,
    /// Kernel version to use.
    #[arg(long)]
    kernel_version: Option<String>,
    /// Preserve the build directory.
    #[arg(long)]
    preserve_builddir: bool,
}

/// Information about stable kernel release from kernel.org.
#[derive(Debug, Deserialize)]
struct KernelRelease {
    version: String,
    moniker: String,
}

/// List of stable kernel releases from kernel.org.
#[derive(Debug, Deserialize)]
struct KernelReleases {
    releases: Vec<KernelRelease>,
}

/// Searches for the latest stable kernel version on kernel.org.
fn latest_version() -> Result<String> {
    let releases: KernelReleases = reqwest::blocking::get(KERNEL_API)?.json()?;

    for release in releases.releases {
        if release.moniker == "stable" {
            return Ok(release.version);
        }
    }

    anyhow::bail!("Could not find the newest stable release")
}

/// Clones the kernel stable git repository.
fn clone_repo(version: &str, destination: &TempDir) -> Result<()> {
    // NOTE(vadorovsky): Sadly, git2 crate doesn't seem to support specyfing
    // depth when cloning.
    Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--branch")
        .arg(format!("v{version}"))
        .arg(REPO_URL)
        .arg(destination.into_os_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(())
}

/// Runs make with appropriate options.
fn make<S>(
    options: &Options,
    arch: Option<&str>,
    cross_compile: Option<&str>,
    builddir: &TempDir,
    arg: S,
) -> Result<()>
where
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new("make");
    cmd.arg(arg);
    if let Some(arch) = arch {
        cmd.arg(format!("ARCH={arch}"));
    }
    if let Some(cross_compile) = cross_compile {
        cmd.arg(format!("CROSS_COMPILE={cross_compile}"));
    }

    cmd.arg(format!("CC={}", options.compiler));
    if let CompilerType::Llvm = options.compiler_type {
        cmd.arg("LLVM=1");
    }
    cmd.current_dir(builddir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(())
}

/// Sets the given kernel config variable.
fn set_config(builddir: &TempDir, action: &str, config: &str) -> Result<()> {
    Command::new("bash")
        .args(["scripts/config", action, config])
        .current_dir(builddir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(())
}

/// Disables the given kernel config variable.
fn disable_config(builddir: &TempDir, config: &str) -> Result<()> {
    set_config(builddir, "--disable", config)
}

/// Enables the given kernel config variable.
fn enable_config(builddir: &TempDir, config: &str) -> Result<()> {
    set_config(builddir, "--enable", config)
}

/// Builds the kernel and generates the BTF header file for the given
/// architecture.
fn generate_vmlinux_for_arch(
    options: &Options,
    version: &str,
    arch: Option<&str>,
    cross_compile: Option<&str>,
    builddir: &TempDir,
    output_path: PathBuf,
    link_path: PathBuf,
) -> Result<()> {
    make(options, arch, cross_compile, builddir, "defconfig")?;
    make(options, arch, cross_compile, builddir, "scripts")?;

    // Disable GDB scripts, we don't need them and they might mangle the debug
    // info configuration.
    disable_config(builddir, "CONFIG_GDB_SCRIPTS")?;

    // Enable all cgroup types.
    enable_config(builddir, "CONFIG_CPUSETS")?;
    enable_config(builddir, "CONFIG_CGROUP_SCHED")?;
    enable_config(builddir, "CONFIG_CGROUP_CPUACCT")?;
    enable_config(builddir, "CONFIG_BLK_CGROUP")?;
    enable_config(builddir, "CONFIG_MEMCG")?;
    enable_config(builddir, "CONFIG_CGROUP_DEVICE")?;
    enable_config(builddir, "CONFIG_CGROUP_FREEZER")?;
    enable_config(builddir, "CONFIG_CGROUP_NET_CLASSID")?;
    enable_config(builddir, "CONFIG_CGROUP_PERF")?;
    enable_config(builddir, "CONFIG_CGROUP_NET_PRIO")?;
    enable_config(builddir, "CONFIG_CGROUP_HUGETLB")?;
    enable_config(builddir, "CONFIG_CGROUP_PIDS")?;
    enable_config(builddir, "CONFIG_CGROUP_RDMA")?;
    enable_config(builddir, "CONFIG_CGROUP_MISC")?;

    // Enable BTF and all BPF features. Even though some of these might not
    // seem directly related from name, they are (DWARF is needed for BTF,
    // page pool stats are related to XDP sockets).
    enable_config(builddir, "CONFIG_FTRACE")?;
    disable_config(builddir, "CONFIG_PSTORE_FTRACE")?;
    disable_config(builddir, "CONFIG_DEBUG_CGROUP_REF")?;
    enable_config(builddir, "CONFIG_KPROBES")?;
    disable_config(builddir, "KPROBE_EVENTS_ON_NOTRACE")?;
    enable_config(builddir, "CONFIG_BLK_DEV_IO_TRACE")?;
    enable_config(builddir, "CONFIG_KPROBE_EVENTS")?;
    enable_config(builddir, "CONFIG_FTRACE_EVENTS")?;
    enable_config(builddir, "CONFIG_USER_EVENTS")?;
    enable_config(builddir, "CONFIG_HAVE_KPROBES_ON_FTRACE")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE_WITH_REGS")?;
    enable_config(builddir, "CONFIG_FTRACE_SYSCALLS")?;
    enable_config(builddir, "CONFIG_FUNCTION_ERROR_INJECTION")?;
    enable_config(builddir, "CONFIG_BPF_KPROBE_OVERRIDE")?;
    enable_config(builddir, "CONFIG_LIRC")?;
    enable_config(builddir, "CONFIG_BPF_LIRC_MODE2")?;
    enable_config(builddir, "CONFIG_FUNCTION_TRACER")?;
    enable_config(builddir, "CONFIG_FUNCTION_GRAPH_TRACER")?;
    enable_config(builddir, "CONFIG_FUNCTION_GRAPH_RETVAL")?;
    enable_config(builddir, "CONFIG_FPROBE")?;
    enable_config(builddir, "CONFIG_FPROBE_EVENTS")?;
    disable_config(builddir, "FTRACE_RECORD_RECURSION")?;
    disable_config(builddir, "CONFIG_FTRACE_SORT_STARTUP_TEST")?;
    enable_config(builddir, "CONFIG_FUNCTION_PROFILER")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE_WITH_ARGS")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE_WITH_CALL_OPS")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS")?;
    enable_config(builddir, "CONFIG_DYNAMIC_FTRACE_WITH_REGS")?;
    enable_config(builddir, "CONFIG_IPV6_SUBTREES")?;
    enable_config(builddir, "CONFIG_IPV6_SEG6_LWTUNNEL")?;
    enable_config(builddir, "CONFIG_IPV6_SEG6_BPF")?;
    enable_config(builddir, "CONFIG_LWTUNNEL")?;
    enable_config(builddir, "CONFIG_LWTUNNEL_BPF")?;
    enable_config(builddir, "CONFIG_HID_BPF")?;
    disable_config(builddir, "CONFIG_DEBUG_INFO_NONE")?;
    enable_config(builddir, "CONFIG_DEBUG_INFO_DWARF5")?;
    enable_config(builddir, "CONFIG_BPF_SYSCALL")?;
    enable_config(builddir, "CONFIG_BPF_UNPRIV_DEFAULT_OFF")?;
    disable_config(builddir, "CONFIG_BPF_PRELOAD")?;
    enable_config(builddir, "CONFIG_CGROUP_BPF")?;
    enable_config(builddir, "CONFIG_XDP_SOCKETS")?;
    enable_config(builddir, "CONFIG_XDP_SOCKETS_DIAG")?;
    enable_config(builddir, "CONFIG_BPF_STREAM_PARSER")?;
    enable_config(builddir, "CONFIG_PAGE_POOL_STATS")?;
    disable_config(builddir, "CONFIG_DEBUG_INFO_REDUCED")?;
    enable_config(builddir, "CONFIG_DEBUG_INFO_COMPRESSED_NONE")?;
    disable_config(builddir, "CONFIG_DEBUG_INFO_COMPRESSED_ZLIB")?;
    disable_config(builddir, "CONFIG_DEBUG_INFO_SPLIT")?;
    disable_config(builddir, "CONFIG_MODULE_ALLOW_BTF_MISMATCH")?;
    enable_config(builddir, "CONFIG_PROBE_EVENTS_BTF_ARGS")?;
    enable_config(builddir, "CONFIG_BPF_LSM")?;
    enable_config(builddir, "CONFIG_DEBUG_INFO_BTF")?;
    enable_config(builddir, "CONFIG_LIVEPATCH")?;

    // Setting the configuration above might trigger prompt for another
    // settings depending on it. In such case, just pick the default values.
    make(options, arch, cross_compile, builddir, "olddefconfig")?;

    make(
        options,
        arch,
        cross_compile,
        builddir,
        format!("-j{}", num_cpus::get()),
    )?;

    let content = Command::new("bpftool")
        .arg("btf")
        .arg("dump")
        .arg("file")
        .arg(builddir.join("vmlinux"))
        .arg("format")
        .arg("c")
        .current_dir(builddir)
        .output()?
        .stdout;

    let _ = fs::remove_file(&link_path);
    let _ = fs::remove_file(&output_path);

    let mut f = File::create(&output_path)?;
    f.write_all(
        "// File autogenerated with `cargo xtask vmlinux`. DO NOT EDIT MANUALLY!\n".as_bytes(),
    )?;
    f.write_all(
        format!(
            "// Kernel {} compiled with {}\n\n",
            version, options.compiler,
        )
        .as_bytes(),
    )?;
    f.write_all(&content)?;
    drop(f);

    symlink(output_path.file_name().unwrap(), &link_path)?;

    make(options, arch, cross_compile, builddir, "clean")?;

    fs::remove_file(builddir.join(".config"))?;

    Ok(())
}

/// Builds kernels and generates BTF header files for all supported
/// architectures.
pub(crate) fn run(options: Options) -> Result<()> {
    // Create a temporary directory
    let builddir = TempDir::new("pulsar-kernel-builddir", options.preserve_builddir)?;

    let version = match options.kernel_version {
        Some(ref kernel_version) => kernel_version.to_owned(),
        None => latest_version()?,
    };
    let sanitized_version = version.replace('.', "_");

    clone_repo(&version, &builddir)?;

    generate_vmlinux_for_arch(
        &options,
        &version,
        None,
        None,
        &builddir,
        PathBuf::from(format!(
            "crates/bpf-builder/include/x86_64/vmlinux_{sanitized_version}.h",
        )),
        PathBuf::from("crates/bpf-builder/include/x86_64/vmlinux.h"),
    )?;
    generate_vmlinux_for_arch(
        &options,
        &version,
        Some("arm"),
        Some("arm-linux-gnueabi-"),
        &builddir,
        PathBuf::from(format!(
            "crates/bpf-builder/include/arm/vmlinux_{sanitized_version}.h",
        )),
        PathBuf::from("crates/bpf-builder/include/arm/vmlinux.h"),
    )?;
    generate_vmlinux_for_arch(
        &options,
        &version,
        Some("arm64"),
        Some("aarch64-linux-gnu-"),
        &builddir,
        PathBuf::from(format!(
            "crates/bpf-builder/include/aarch64/vmlinux_{sanitized_version}.h",
        )),
        PathBuf::from("crates/bpf-builder/include/aarch64/vmlinux.h"),
    )?;
    generate_vmlinux_for_arch(
        &options,
        &version,
        Some("riscv"),
        Some("riscv64-linux-gnu-"),
        &builddir,
        PathBuf::from(format!(
            "crates/bpf-builder/include/riscv64/vmlinux_{sanitized_version}.h",
        )),
        PathBuf::from("crates/bpf-builder/include/riscv64/vmlinux.h"),
    )?;

    if !options.preserve_builddir {
        fs::remove_dir_all(&builddir)?;
    }

    Ok(())
}
