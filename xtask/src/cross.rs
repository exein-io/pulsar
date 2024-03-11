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

#[derive(Debug, Parser)]
pub(crate) struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    /// Build binary and copy it to destination folder
    Build {
        /// Where to copy the file
        #[clap(long, default_value = "/tmp/")]
        destination: String,

        #[command(flatten)]
        opts: SharedOptions,
    },
    /// Run over the given SSH connection.
    Run {
        /// Target ssh
        #[clap(long, default_value = "root@localhost")]
        ssh_target: String,

        /// SSH port
        #[clap(long, default_value_t = 3366)]
        ssh_port: u16,

        // Preserve the temporary directory with architest artifacts.
        #[arg(long)]
        preserve_tempdir: bool,

        /// Arguments passed on process execution
        args: Vec<String>,

        #[command(flatten)]
        opts: SharedOptions,
    },
}

#[derive(Debug, Parser)]
struct SharedOptions {
    /// Target architecture
    #[clap(long, default_value = "x86_64-unknown-linux-musl")]
    target: String,

    /// Binary to compile
    #[clap(long, default_value = "test-suite")]
    binary: String,

    /// Build and run the release target
    #[clap(long)]
    release: bool,
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
        format!("https://github.com/exein-io/architest/releases/download/0.4/{architest_tarball}");
    let tarball_path = tempdir.join(architest_tarball);

    download_tarball(&url, &tarball_path)?;
    extract_tarball(tempdir, &tarball_path)?;

    Ok(())
}

pub(crate) fn run(options: Options) -> Result<()> {
    let sh = Shell::new()?;
    let SharedOptions {
        target,
        binary,
        release,
    } = match &options.command {
        Command::Build { opts, .. } => opts,
        Command::Run { opts, .. } => opts,
    };
    let args = if *release { Some("--release") } else { None };
    cmd!(
        sh,
        "cross build --target {target} --target-dir target/cross --workspace --bin {binary} {args...}"
    )
    .run()?;
    let build_type = if *release { "release" } else { "debug" };
    let binary_file = format!(
        "{}/target/cross/{target}/{build_type}/{binary}",
        std::env::current_dir()?.display()
    );
    cmd!(sh, "llvm-strip {binary_file}").run()?;
    match &options.command {
        Command::Build {
            destination,
            opts: _,
        } => cmd!(sh, "cp {binary_file} {destination}").run()?,
        Command::Run {
            ssh_target,
            ssh_port,
            preserve_tempdir: preserve_builddir,
            args,
            opts: _,
        } => {
            let tempdir = TempDir::new("pulsar-architest", *preserve_builddir);
            tempdir.create()?;
            sh.change_dir(&tempdir);

            let (architest_tarball, qemu_cmd, qemu_args) = match target.as_str() {
                "aarch64-unknown-linux-musl" => (
                    "aarch64_6.6.tar.gz",
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
                    "x86_64_6.6.tar.gz",
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

            download_and_unpack_architest(&tempdir, architest_tarball)?;

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

            let ssh_port = ssh_port.to_string();

            cmd!(sh, "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P {ssh_port} {binary_file} {ssh_target}:/tmp/").run()?;
            cmd!(sh, "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_target} -p {ssh_port} /tmp/{binary} {args...}").run()?;

            qemu_process.kill()?;
            qemu_process.wait()?;
        }
    }
    Ok(())
}
