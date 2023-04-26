use bpf_common::Pid;
use pulsar_core::pdk::{ConfigError, ModuleConfig};

use crate::maps::{DEFAULT_INTEREST, DEFAULT_RULES};

use super::maps::Image;

/// [`Config`] is the user configuration of a list of rules
/// for determining what constitutes an interesting eBPF event.
#[derive(Clone, Debug, Default)]
pub(crate) struct Config {
    /// List of Pid-based rules
    pub(crate) pid_targets: Vec<PidRule>,
    /// List of image-based rules
    pub(crate) rules: Vec<Rule>,
    /// Map name of the interest map
    pub(crate) interest_map_name: String,
    /// Map name of the rules map
    pub(crate) rule_map_name: String,
    /// Sets the default tracking status for Pid 1 and when finding missing entries.
    pub(crate) track_by_default: bool,
    /// Whitelist the current process
    pub(crate) ignore_self: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct Rule {
    /// This rule applies to all processes matching this process name
    pub(crate) image: Image,
    /// If true, the given process is tracked. if false, it is whitelisted.
    pub(crate) track: bool,
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
                    with_children: true,
                }),
        );
        let mut rules = Vec::new();
        for (field, track, with_children) in [
            ("targets", true, false),
            ("targets_children", true, true),
            ("whitelist", false, false),
            ("whitelist_children", false, true),
        ] {
            rules.extend(config.get_list(field)?.into_iter().map(move |image| Rule {
                image,
                track,
                with_children,
            }));
        }

        Ok(Config {
            pid_targets,
            rules,
            interest_map_name: DEFAULT_INTEREST.to_string(),
            rule_map_name: DEFAULT_RULES.to_string(),
            track_by_default: config.with_default("track_by_default", true)?,
            ignore_self: config.with_default("ignore_self", true)?,
        })
    }
}
