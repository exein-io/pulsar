use anyhow::{bail, Context, Result};
use clap::Parser;
use xshell::{cmd, Shell};

#[derive(Debug, Parser)]
pub struct SuRunCommand {
    /// Arguments normally passed to `cargo run`
    #[clap(name = "ARGS", allow_hyphen_values = true)]
    pub run_args: Vec<String>,
}

impl SuRunCommand {
    pub fn run(&self) -> Result<()> {
        let cargo = std::env::var("CARGO").unwrap();

        // To determine the target triple it checks in order:
        // - `--target` command line option
        // - `CARGO_BUILD_TARGET` environment variable
        // - default host target
        //
        // TODO: it should check also hierarchical `config.toml` files as described
        // in the following page:
        // https://doc.rust-lang.org/cargo/reference/config.html#hierarchical-structure
        let target_triple = match self
            .run_args
            .iter()
            .skip_while(|arg| *arg != "--target")
            .nth(1) // skip the `--target` identifier
        {
            Some(target_triple) => target_triple.to_owned(),
            None => {
                const TARGET_TRIPLE_ENV: &str = "CARGO_BUILD_TARGET";

                match std::env::var(TARGET_TRIPLE_ENV) {
                    Ok(target_triple) => target_triple,
                    Err(std::env::VarError::NotPresent) => {
                        get_default_target(&cargo)
                            .context(format!("failed to get target triple with {cargo}"))?
                    }
                    Err(std::env::VarError::NotUnicode(var)) => {
                        bail!("env variable `{TARGET_TRIPLE_ENV}` doesn't contain a valid unicode: {var:?}")
                    }
                }
            }
        };

        log::debug!("Detected host triple: {target_triple}");

        let target_triple_env_runner = {
            let tt_env_format = target_triple.to_uppercase().replace("-", "_");
            format!("CARGO_TARGET_{tt_env_format}_RUNNER")
        };

        log::debug!("Overriding env variable: {target_triple_env_runner}");

        let sh = Shell::new()?;

        sh.set_var(target_triple_env_runner, "sudo -E");

        let args = &self.run_args;

        cmd!(sh, "{cargo} run {args...}").run()?;

        Ok(())
    }
}

/// Calls `cargo -vV`` in a subprocess and returns the default Clang target triple.
fn get_default_target(cargo_path: &str) -> Result<String> {
    /// The [`rustc`][1] output field name that shows the target.
    ///
    /// [1]: https://doc.rust-lang.org/rustc/what-is-rustc.html
    const TARGET_FIELD: &str = "host: ";

    // Query rustc for defaults.
    let output = std::process::Command::new(cargo_path)
        .arg("-vV")
        .output()
        .context(format!("failed to execute `{cargo_path} -vV`"))?;

    // Decode stdout.
    let stdout = std::str::from_utf8(&output.stdout).context("failed to read stdout into uft8")?;

    // Parse the default target from stdout.
    stdout
        .lines()
        .find(|l| l.starts_with(TARGET_FIELD))
        .map(|l| &l[TARGET_FIELD.len()..])
        .context(format!("failed to parse target from {cargo_path} output"))
        .map(str::to_owned)
}
