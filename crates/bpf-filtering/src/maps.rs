use std::{fmt, str::FromStr};

use anyhow::{Context, Result};
use bpf_common::{aya, Pid};

use super::config::{Rule, MAX_IMAGE_LEN};

type Map<K, V> = aya::maps::HashMap<aya::maps::MapData, K, V>;

/// This map assigns to every running process a PolicyDecision:
/// - Are we interested in events generated by this process?
/// - Are we interested in events generated by its children?
pub(crate) struct InterestMap(pub(crate) Map<i32, u8>);

/// Default name for map interest
pub const DEFAULT_INTEREST: &str = "m_interest";

/// Default name for rules map
pub const DEFAULT_RULES: &str = "m_rules";

impl InterestMap {
    /// Try to load the map from eBPF
    pub(crate) fn load(bpf: &mut aya::Bpf, name: &str) -> Result<Self> {
        load_map(bpf, name).map(Self)
    }

    /// Clear the map
    pub(crate) fn clear(&mut self) -> Result<()> {
        clear_map(&mut self.0, "interest map")
    }

    /// Update the interest map by setting the policy decision of a given process
    pub(crate) fn set(&mut self, pid: Pid, policy_result: PolicyDecision) -> Result<()> {
        self.0
            .insert(pid.as_raw(), policy_result.as_raw(), 0)
            .context("Error inserting entry in map_interest")?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PolicyDecision {
    pub(crate) interesting: bool,
    pub(crate) children_interesting: bool,
}

impl PolicyDecision {
    /// Convert the `PolicyDecision` to a bit field
    pub(crate) fn as_raw(&self) -> u8 {
        match (self.children_interesting, self.interesting) {
            (false, false) => 0,
            (false, true) => 1,
            (true, false) => 2,
            (true, true) => 3,
        }
    }
}

/// A RuleMap contains the target/whitelist images and weather or not the rule
/// should affect its children.
pub(crate) struct RuleMap(Map<Image, u8>);

impl RuleMap {
    /// Try to load the rule map
    pub(crate) fn load(bpf: &mut aya::Bpf, name: &str) -> Result<Self> {
        load_map(bpf, name).map(Self)
    }

    /// Clear the map
    pub(crate) fn clear(&mut self) -> Result<()> {
        clear_map(&mut self.0, "rule map")
    }

    /// Fill the map with a list of rules
    pub(crate) fn install(&mut self, rules: &[Rule]) -> Result<()> {
        for rule in rules {
            let value: u8 = match (rule.with_children, rule.track) {
                (false, false) => 0,
                (false, true) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            self.0
                .insert(rule.image, value, 0)
                .with_context(|| format!("Error inserting rule for {}", rule.image))?;
        }
        Ok(())
    }
}

/// Try to load the eBPF hash map with the given name
fn load_map<K, V>(bpf: &mut aya::Bpf, name: &str) -> Result<Map<K, V>>
where
    K: aya::Pod,
    V: aya::Pod,
{
    Map::try_from(
        bpf.take_map(name)
            .with_context(|| format!("Error finding eBPF map {name}"))?,
    )
    .with_context(|| format!("Error loading eBPF map {name} as HashMap"))
}

/// Remove all entries from the given eBPF hash map
fn clear_map<K, V>(map: &mut Map<K, V>, name: &str) -> Result<()>
where
    K: aya::Pod,
    V: aya::Pod,
{
    let old_keys: Result<Vec<_>, _> = map.keys().collect();
    old_keys
        .with_context(|| format!("Error getting keys to be cleared from {name}"))?
        .iter()
        .try_for_each(|image| map.remove(image))
        .with_context(|| format!("Error clearing entry from {name}"))?;
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Image(pub(crate) [u8; MAX_IMAGE_LEN]);
// We must explicitly mark Image as a plain old data which can be safely memcopied by aya.
unsafe impl bpf_common::aya::Pod for Image {}

#[derive(thiserror::Error, Debug)]
pub enum InvalidImage {
    #[error("process image coming from string must be ascii")]
    NotAscii,
    #[error("process image must be smaller than {MAX_IMAGE_LEN}")]
    TooLong,
}

impl TryFrom<Vec<u8>> for Image {
    type Error = InvalidImage;

    fn try_from(mut data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.len() > MAX_IMAGE_LEN {
            return Err(InvalidImage::TooLong);
        }
        data.resize(MAX_IMAGE_LEN, 0);
        let mut image_array = [0; MAX_IMAGE_LEN];
        image_array.clone_from_slice(&data[..]);
        Ok(Image(image_array))
    }
}

impl FromStr for Image {
    type Err = InvalidImage;

    fn from_str(image: &str) -> Result<Self, Self::Err> {
        if !image.is_ascii() {
            Err(InvalidImage::NotAscii)
        } else if image.len() >= MAX_IMAGE_LEN {
            Err(InvalidImage::TooLong)
        } else {
            let data: Vec<u8> = image.bytes().collect();
            Image::try_from(data)
        }
    }
}

impl fmt::Display for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.into_iter().take_while(|c| *c != 0) {
            write!(f, "{}", c as char)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Image").field(&self.to_string()).finish()
    }
}
