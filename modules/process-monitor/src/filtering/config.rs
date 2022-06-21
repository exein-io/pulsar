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
    pub(crate) image: String,
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
        targets.extend(config.get_list("targets")?.into_iter().map(|image| Rule {
            image,
            with_children: false,
        }));
        targets.extend(
            config
                .get_list("targets_children")?
                .into_iter()
                .map(|image| Rule {
                    image,
                    with_children: true,
                }),
        );
        let mut whitelist = Vec::new();
        whitelist.extend(config.get_list("whitelist")?.into_iter().map(|image| Rule {
            image,
            with_children: false,
        }));
        whitelist.extend(
            config
                .get_list("whitelist_children")?
                .into_iter()
                .map(|image| Rule {
                    image,
                    with_children: true,
                }),
        );

        Ok(Config {
            pid_targets,
            targets,
            whitelist,
        })
    }
}
