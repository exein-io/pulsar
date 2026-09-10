use anyhow::{Context, Result};
use bpf_common::Pid;
use serde::{Deserialize, Deserializer, de};

use crate::maps::{DEFAULT_INTEREST, DEFAULT_RULES};

use super::maps::Image;

/// [`Config`] is the user configuration of a list of rules
/// for determining what constitutes an interesting eBPF event.
#[derive(Clone, Debug)]
pub struct Config {
    /// List of Pid-based rules
    pub pid_targets: Vec<PidRule>,
    /// List of image-based rules
    pub rules: Vec<Rule>,
    /// Map name of the interest map
    pub interest_map_name: String,
    /// Map name of the rules map
    pub rule_map_name: String,
    /// Sets the default tracking status for Pid 1 and when finding missing entries.
    pub track_by_default: bool,
    /// Whitelist the current process
    pub ignore_self: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pid_targets: Vec::new(),
            rules: Vec::new(),
            interest_map_name: DEFAULT_INTEREST.to_string(),
            rule_map_name: DEFAULT_RULES.to_string(),
            track_by_default: true,
            ignore_self: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    /// This rule applies to all processes matching this process name
    pub image: Image,
    /// If true, the given process is tracked. if false, it is whitelisted.
    pub track: bool,
    /// If true, this rule is applied to all children of this process
    /// until a new rule with `with_children=true` applies.
    pub with_children: bool,
}

/// Rule for targeting a specific PID optionally its children
#[derive(Clone, Debug)]
pub struct PidRule {
    pub pid: Pid,
    pub with_children: bool,
}

pub const MAX_IMAGE_LEN: usize = 100;

// TODO: the six lists below collapse into `Config::rules` and
// `Config::pid_targets`, and the two map names are not user configurable. Both
// should be lifted out of `Config` so this intermediate struct can go away.
#[derive(Deserialize)]
#[serde(default)]
struct RawConfig {
    /// Pids to track.
    pid_targets: Vec<i32>,
    /// Pids to track, extended to their children.
    pid_targets_children: Vec<i32>,
    /// Process images to track.
    targets: Vec<String>,
    /// Process images to track, extended to their children.
    targets_children: Vec<String>,
    /// Process images to ignore.
    whitelist: Vec<String>,
    /// Process images to ignore, extended to their children.
    whitelist_children: Vec<String>,
    /// Tracking status of Pid 1 and of processes matching no rule.
    track_by_default: bool,
    /// Add the Pulsar executable to `whitelist_children`.
    ignore_self: bool,
}

impl Default for RawConfig {
    fn default() -> Self {
        Self {
            pid_targets: Vec::new(),
            pid_targets_children: Vec::new(),
            targets: Vec::new(),
            targets_children: Vec::new(),
            whitelist: Vec::new(),
            whitelist_children: Vec::new(),
            track_by_default: true,
            ignore_self: true,
        }
    }
}

impl TryFrom<RawConfig> for Config {
    type Error = anyhow::Error;

    fn try_from(raw: RawConfig) -> Result<Self> {
        let mut pid_targets = Vec::new();
        for (pids, with_children) in [(raw.pid_targets, false), (raw.pid_targets_children, true)] {
            pid_targets.extend(pids.into_iter().map(|pid| PidRule {
                pid: Pid::from_raw(pid),
                with_children,
            }));
        }

        let mut rules = Vec::new();
        for (images, track, with_children) in [
            (raw.targets, true, false),
            (raw.targets_children, true, true),
            (raw.whitelist, false, false),
            (raw.whitelist_children, false, true),
        ] {
            for image in images {
                let image = image
                    .parse()
                    .with_context(|| format!("invalid process image '{image}'"))?;
                rules.push(Rule {
                    image,
                    track,
                    with_children,
                });
            }
        }

        Ok(Config {
            pid_targets,
            rules,
            track_by_default: raw.track_by_default,
            ignore_self: raw.ignore_self,
            ..Default::default()
        })
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = RawConfig::deserialize(deserializer)?;
        Config::try_from(raw).map_err(|err| de::Error::custom(format!("{err:#}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(content: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(content)
    }

    #[test]
    fn empty_section_keeps_defaults() {
        let config = parse("").unwrap();
        assert!(config.rules.is_empty());
        assert!(config.pid_targets.is_empty());
        assert!(config.track_by_default);
        assert!(config.ignore_self);
        assert_eq!(config.interest_map_name, DEFAULT_INTEREST);
        assert_eq!(config.rule_map_name, DEFAULT_RULES);
    }

    #[test]
    fn image_lists_collapse_into_rules() {
        let config = parse(
            r#"
            targets = ["/usr/bin/a"]
            targets_children = ["/usr/bin/b"]
            whitelist = ["/usr/bin/c"]
            whitelist_children = ["/usr/bin/d"]
            "#,
        )
        .unwrap();

        let rules: Vec<_> = config
            .rules
            .iter()
            .map(|r| (r.image.to_string(), r.track, r.with_children))
            .collect();
        assert_eq!(
            rules,
            [
                ("/usr/bin/a".to_string(), true, false),
                ("/usr/bin/b".to_string(), true, true),
                ("/usr/bin/c".to_string(), false, false),
                ("/usr/bin/d".to_string(), false, true),
            ]
        );
    }

    #[test]
    fn pid_lists_collapse_into_pid_targets() {
        let config = parse("pid_targets = [1]\npid_targets_children = [2]\n").unwrap();
        let targets: Vec<_> = config
            .pid_targets
            .iter()
            .map(|r| (r.pid.as_raw(), r.with_children))
            .collect();
        assert_eq!(targets, [(1, false), (2, true)]);
    }

    #[test]
    fn invalid_image_is_rejected() {
        let too_long = "x".repeat(MAX_IMAGE_LEN);
        let err = parse(&format!("targets = [\"{too_long}\"]")).unwrap_err();
        assert!(err.to_string().contains("invalid process image"));
    }
}
