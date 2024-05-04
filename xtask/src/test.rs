use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result};
use clap::Parser;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use tar::Archive;
use xshell::{cmd, Shell};

use crate::tempdir::TempDir;

const ARCHITEST_VERSION: &str = "0.4";

#[derive(Debug, Parser)]
pub(crate) struct Options {
    /// Target architecture. It can be different than the host.
    #[clap(long, default_value = "x86_64-unknown-linux-musl")]
    target: String,

    /// Preserve the temporary directory with architest artifacts (relevant
    /// only for cross builds).
    #[arg(long)]
    preserve_tempdir: bool,

    /// Build and run the release target.
    #[clap(long)]
    release: bool,

    /// Space or comma separated list of features to activate.
    #[clap(short, long)]
    features: Vec<String>,

    /// Use architest/QEMU even for a native target.
    #[clap(long)]
    force_architest: bool,

    /// Kernel version to use in architest/QEMU.
    #[clap(long, default_value = "6.6")]
    kernel_version: String,
}

fn download_tarball<P>(url: &str, tarball_path: P) -> Result<()>
where
    P: AsRef<Path> + std::fmt::Debug,
{
    let mut response = reqwest::blocking::get(url)?;
    let content_length = response
        .content_length()
        .ok_or(anyhow::anyhow!("Failed to get content length of {url}"))?;

    let pb = ProgressBar::new(content_length).with_message("Downloading architest archive");
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")?
        .progress_chars("#>-"));

    let mut file = File::create(tarball_path)?;
    let mut buffer = vec![0; 4096];
    let mut downloaded: u64 = 0;

    while downloaded < content_length {
        let bytes_read = response.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        file.write_all(&buffer[..bytes_read])?;
        downloaded += bytes_read as u64;
        pb.set_position(downloaded);
    }

    pb.finish_with_message("Download complete");

    Ok(())
}

fn extract_tarball<P>(tempdir: &TempDir, tarball_path: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let file = File::open(tarball_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    archive.unpack(tempdir)?;

    Ok(())
}

fn download_and_unpack_architest(tempdir: &TempDir, architest_tarball: &str) -> Result<()> {
    let url =
        format!("https://github.com/exein-io/architest/releases/download/{ARCHITEST_VERSION}/{architest_tarball}");
    let tarball_path = tempdir.join(architest_tarball);

    download_tarball(&url, &tarball_path)?;
    extract_tarball(tempdir, &tarball_path)?;

    Ok(())
}

fn test_architest(sh: Shell, options: Options, binary_file: &str) -> Result<()> {
    let Options {
        target,
        preserve_tempdir,
        kernel_version,
        ..
    } = options;

    let tempdir = TempDir::new("pulsar-architest", preserve_tempdir)?;
    sh.change_dir(&tempdir);

    let (architest_tarball, qemu_cmd, qemu_args) = match target.as_str() {
        "aarch64-unknown-linux-musl" => (
            format!("aarch64_{kernel_version}.tar.gz"),
            "qemu-system-aarch64",
            vec![
                "-M",
                "virt",
                "-cpu",
                "cortex-a53",
                "-smp",
                "1",
                "-kernel",
                "Image",
                "-append",
                "rootwait root=/dev/vda console=ttyAMA0",
                "-drive",
                "file=rootfs.ext2,if=none,format=raw,id=hd0",
                "-device",
                "virtio-blk-device,drive=hd0",
                "-m",
                "1024M",
                "-nographic",
                "-nic",
                "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:3366-10.0.2.14:22",
            ],
        ),
        "x86_64-unknown-linux-musl" => (
            format!("x86_64_{kernel_version}.tar.gz"),
            "qemu-system-x86_64",
            vec![
                "-M",
                "pc",
                "-kernel",
                "bzImage",
                "-drive",
                "file=rootfs.ext2,if=virtio,format=raw",
                "-append",
                "rootwait root=/dev/vda console=tty1 console=ttyS0",
                "-m",
                "1024M",
                "-nographic",
                "-nic",
                "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:3366-10.0.2.14:22",
            ],
        ),
        _ => return Err(anyhow::anyhow!("Unsupported target: {target}")),
    };

    download_and_unpack_architest(&tempdir, &architest_tarball)?;

    cmd!(sh, "truncate -s +200M rootfs.ext2").run()?;
    let loop_dev = cmd!(sh, "sudo losetup -fP --show rootfs.ext2").output()?;
    let loop_dev = String::from_utf8(loop_dev.stdout)?;
    let loop_dev = loop_dev.trim_end();
    cmd!(sh, "sudo resize2fs {loop_dev}").run()?;
    cmd!(sh, "sudo losetup -d {loop_dev}").run()?;

    // Run qemu
    let mut qemu_process = std::process::Command::new(qemu_cmd)
        .args(qemu_args)
        .current_dir(&tempdir)
        .spawn()
        .context("Failed to run QEMU")?;
    // Give QEMU some time to start
    std::thread::sleep(std::time::Duration::from_secs(12));

    cmd!(sh, "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P 3366 {binary_file} root@localhost:/tmp/").run()?;
    cmd!(sh, "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost -p 3366 /tmp/test-suite").run()?;

    qemu_process.kill()?;
    qemu_process.wait()?;

    Ok(())
}

pub(crate) fn run(options: Options) -> Result<()> {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        anyhow::bail!("The host CPU architecture is unsupported");
    };

    let Options {
        target,
        release,
        features,
        force_architest,
        ..
    } = &options;
    let mut args = Vec::new();
    if *release { args.push("--release") }
    for feature in features {
        args.push("--features");
        args.push(feature);
    }
    let build_type = if *release { "release" } else { "debug" };
    let binary_file = format!(
        "{}/target/cross/{target}/{build_type}/test-suite",
        std::env::current_dir()?.display()
    );

    let sh = Shell::new()?;

    cmd!(
        sh,
        "cross build --target {target} --target-dir target/cross --workspace --bin test-suite {args...}"
    )
    .run()?;

    if *force_architest || !target.starts_with(arch) {
        test_architest(sh, options, &binary_file)?;
    } else {
        cmd!(sh, "sudo -E {binary_file}").run()?;
    }

    Ok(())
}
