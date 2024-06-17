use std::{env, ffi::OsString};

use clap::{Arg, ArgAction, Command, CommandFactory, FromArgMatches};

pub mod pulsar;
pub mod pulsard;

#[derive(Debug, Clone)]
pub enum Mode {
    PulsarCli(pulsar::PulsarCliOpts),
    PulsarDaemon(pulsard::PulsarDaemonOpts),
}

#[derive(Debug, Clone)]
pub struct PulsarExecOpts {
    pub mode: Mode,
    pub override_log_level: log::Level,
}

pub fn parse_from_args() -> PulsarExecOpts {
    parse_from(&mut std::env::args_os())
}

pub fn parse_from<I, T>(args: I) -> PulsarExecOpts
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    try_parse_from(args).unwrap_or_else(|e| e.exit())
}

pub fn try_parse_from<I, T>(args: I) -> Result<PulsarExecOpts, clap::Error>
where
    I: Iterator<Item = T>,
    T: Into<OsString> + Clone,
{
    // We wand different help templates depending on how the executable is invoked
    let template_kind = match env::var("MASK_LAUNCHER") {
        Ok(v) if v == "1" => HelpTemplate::MaskedSubcommand,
        _ => HelpTemplate::RawSubcommand,
    };

    let template = help_template("pulsar-exec", HelpTemplate::RawExecutable, true, true);
    let daemon_template = help_template(pulsard::NAME, template_kind, true, false);
    let cli_template = help_template(pulsar::NAME, template_kind, true, true);

    let daemon_app = pulsard::PulsarDaemonOpts::command().help_template(daemon_template);
    let cli_app = pulsar::PulsarCliOpts::command().help_template(cli_template);

    let matches = Command::new("pulsar-exec")
        .version(crate::version())
        .about("Pulsar executables launcher")
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .disable_help_subcommand(true)
        .help_template(template)
        .subcommand(with_verbosity_flag(daemon_app))
        .subcommand(with_verbosity_flag(cli_app))
        .try_get_matches_from(args)?;

    let override_log_level;
    let mode = match matches.subcommand() {
        Some((exec_name, matches)) => {
            // Handle verbosity flag
            override_log_level = log_level_from_verbosity_flag_count(matches.get_count("v"));

            // Handle subcommand
            match exec_name {
                pulsard::NAME => {
                    Mode::PulsarDaemon(pulsard::PulsarDaemonOpts::from_arg_matches(matches)?)
                }
                pulsar::NAME => Mode::PulsarCli(pulsar::PulsarCliOpts::from_arg_matches(matches)?),
                _ => unreachable!("Subcommand should be specified"),
            }
        }
        None => unreachable!("Subcommand should be specified"),
    };

    Ok(PulsarExecOpts {
        override_log_level,
        mode,
    })
}

fn with_verbosity_flag(app: Command) -> Command {
    app.arg(
        Arg::new("v")
            .short('v')
            .long("verbose")
            .action(ArgAction::Count)
            .help("Pass many times for a more verbose output. Passing `-v` adds debug logs, `-vv` enables trace logging"),
    )
}

fn log_level_from_verbosity_flag_count(num: u8) -> log::Level {
    match num {
        u8::MIN..=0 => log::Level::Info,
        1 => log::Level::Debug,
        2..=u8::MAX => log::Level::Trace,
    }
}

fn show_backtrace() -> bool {
    if log::max_level() >= log::LevelFilter::Debug {
        return true;
    }

    if let Ok(true) = env::var("RUST_BACKTRACE").map(|s| s == "1") {
        return true;
    }

    false
}

pub fn report_error(e: &anyhow::Error) {
    // NB: This shows one error: even for multiple causes and backtraces etc,
    // rather than one per cause, and one for the backtrace. This seems like a
    // reasonable tradeoff, but if we want to do differently, this is the code
    // hunk to revisit, that and a similar build.rs auto-detect glue as anyhow
    // has to detect when backtrace is available.
    if show_backtrace() {
        log::error!("{:?}", e);
    } else {
        log::error!("{:#}", e);
    }
}

/// Replace executable name depending on how we've been invoked
fn help_template(
    name: &str,
    template_kind: HelpTemplate,
    options: bool,
    subcommand: bool,
) -> String {
    let prefix = match template_kind {
        HelpTemplate::RawSubcommand => "pulsar-exec ",
        HelpTemplate::RawExecutable | HelpTemplate::MaskedSubcommand => "",
    };

    let options = if options { "[OPTIONS]" } else { "" };
    let subcommand = if subcommand { "<SUBCOMMAND>" } else { "" };

    format!(
        "\
{{about}}

{{usage-heading}}
  {prefix}{name} {options} {subcommand}

{{all-args}}\
"
    )
}

#[derive(Clone, Copy)]
enum HelpTemplate {
    RawExecutable,
    MaskedSubcommand,
    RawSubcommand,
}
