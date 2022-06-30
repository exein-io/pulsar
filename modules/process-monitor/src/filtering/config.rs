use std::str::FromStr;

use bpf_common::Pid;
use pulsar_core::pdk::{ConfigError, ModuleConfig};

/// [`Config`] is the user configuration of a list of rules
/// for determining what constitutes an interesting eBPF event.
#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    pub(crate) pid_targets: Vec<PidRule>,
    pub(crate) targets: Vec<Rule>,
    pub(crate) whitelist: Vec<Rule>,
}

#[derive(Clone, Debug)]
pub(crate) struct Rule {
    /// This rule applies to all processes matching this process name
    pub(crate) image: Image,
    /// If true, this rule is applied to all children of this process
    /// until a new rule with `with_children=true` applies.
    pub(crate) with_children: bool,
}

/// Rule for targeting a specific PID optionally its children
#[derive(Clone, Debug)]
pub(crate) struct PidRule {
    pub(crate) pid: Pid,
    pub(crate) with_children: bool,
}

pub const MAX_IMAGE_LEN: usize = 100;

/// Extract Config from configuration file
impl TryFrom<&ModuleConfig> for Config {
    type Error = ConfigError;

    fn try_from(config: &ModuleConfig) -> Result<Self, Self::Error> {
        let mut pid_targets = Vec::new();
        pid_targets.extend(config.get_list("pid_targets")?.iter().map(|pid| PidRule {
            pid: Pid::from_raw(*pid),
            with_children: false,
        }));
        pid_targets.extend(
            config
                .get_list("pid_targets_children")?
                .iter()
                .map(|pid| PidRule {
                    pid: Pid::from_raw(*pid),
                    with_children: false,
                }),
        );
        let mut targets = Vec::new();
        targets.extend(get_rules(config, "targets", false)?);
        targets.extend(get_rules(config, "targets_children", true)?);
        let mut whitelist = Vec::new();
        whitelist.extend(get_rules(config, "whitelist", false)?);
        whitelist.extend(get_rules(config, "whitelist_children", true)?);

        Ok(Config {
            pid_targets,
            targets,
            whitelist,
        })
    }
}

/// Create a list of rules from the given config field, which must contain
/// a list of process images
fn get_rules(
    config: &ModuleConfig,
    field: &'static str,
    with_children: bool,
) -> Result<impl Iterator<Item = Rule>, ConfigError> {
    Ok(config.get_list(field)?.into_iter().map(move |image| Rule {
        image,
        with_children,
    }))
}

/// Process name. Invariant: this is valid ASCII and smaller than MAX_IMAGE_LEN
#[derive(Clone, Debug)]
pub(crate) struct Image(Vec<u8>);

impl Image {
    pub(crate) fn as_vec(&self) -> &Vec<u8> {
        &self.0
    }
}

impl FromStr for Image {
    type Err = String;

    fn from_str(image: &str) -> Result<Self, Self::Err> {
        if !image.is_ascii() {
            Err("process image must be ascii".to_string())
        } else if image.len() >= MAX_IMAGE_LEN {
            Err(format!(
                "process image must be smaller than {MAX_IMAGE_LEN}"
            ))
        } else {
            Ok(Image(image.bytes().collect()))
        }
    }
}
