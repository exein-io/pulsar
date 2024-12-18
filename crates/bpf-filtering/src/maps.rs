use std::{fmt, str::FromStr};

use anyhow::{Context, Result};
use bpf_common::{aya, Pid};

use super::config::{Rule, MAX_CGROUP_LEN, MAX_IMAGE_LEN};

/// This map assigns to every running process a PolicyDecision:
/// - Are we interested in events generated by this process?
/// - Are we interested in events generated by its children?
pub struct InterestMap(pub(crate) Map<i32, u8>);

/// Default name for map interest
pub const DEFAULT_INTEREST: &str = "m_interest";

/// Default name for rules map
pub const DEFAULT_RULES: &str = "m_rules";
pub const DEFAULT_CGROUP_RULES: &str = "m_cgroup_rules";

impl InterestMap {
    /// Try to load the map from eBPF
    pub fn load(bpf: &mut aya::Ebpf, name: &str) -> Result<Self> {
        Map::load(bpf, name).map(Self)
    }

    /// Clear the map
    pub fn clear(&mut self) -> Result<()> {
        self.0.clear()
    }

    /// Update the interest map by setting the policy decision of a given process
    pub fn set(&mut self, pid: Pid, policy_result: PolicyDecision) -> Result<()> {
        self.0
            .map
            .insert(pid.as_raw(), policy_result.as_raw(), 0)
            .context("Error inserting entry in map_interest")?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct PolicyDecision {
    pub interesting: bool,
    pub children_interesting: bool,
}

impl PolicyDecision {
    /// Convert the `PolicyDecision` to a bit field
    pub fn as_raw(&self) -> u8 {
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
pub struct RuleMap(Map<Image, u8>);

impl RuleMap {
    /// Try to load the rule map
    pub fn load(bpf: &mut aya::Ebpf, name: &str) -> Result<Self> {
        Map::load(bpf, name).map(Self)
    }

    /// Clear the map
    pub fn clear(&mut self) -> Result<()> {
        self.0.clear()
    }

    /// Fill the map with a list of rules
    pub fn install(&mut self, rules: &[Rule]) -> Result<()> {
        for rule in rules {
            let value: u8 = match (rule.with_children, rule.track) {
                (false, false) => 0,
                (false, true) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            self.0
                .map
                .insert(rule.image, value, 0)
                .with_context(|| format!("Error inserting rule for {}", rule.image))?;
        }
        Ok(())
    }
}

pub(crate) struct Map<K, V> {
    pub(crate) name: String,
    pub(crate) map: aya::maps::HashMap<aya::maps::MapData, K, V>,
}

impl<K: aya::Pod, V: aya::Pod> Map<K, V> {
    /// Try to load the eBPF hash map with the given name
    pub(crate) fn load(bpf: &mut aya::Ebpf, name: &str) -> Result<Self> {
        let map = aya::maps::HashMap::try_from(
            bpf.take_map(name)
                .with_context(|| format!("Error finding eBPF map {name}"))?,
        )
        .with_context(|| format!("Error loading eBPF map {name} as HashMap"))?;
        Ok(Self {
            map,
            name: name.to_string(),
        })
    }

    /// Remove all entries from the given eBPF hash map
    pub(crate) fn clear(&mut self) -> Result<()> {
        let old_keys: Result<Vec<_>, _> = self.map.keys().collect();
        old_keys
            .with_context(|| format!("Error getting keys to be cleared from {}", self.name))?
            .iter()
            .try_for_each(|image| self.map.remove(image))
            .with_context(|| format!("Error clearing entry from {}", self.name))?;
        Ok(())
    }
}

pub type Image = CharArray<MAX_IMAGE_LEN>;
pub type Cgroup = CharArray<MAX_CGROUP_LEN>;

#[derive(Clone, Copy)]
pub struct CharArray<const N: usize>(pub [u8; N]);
// We must explicitly mark Image as a plain old data which can be safely memcopied by aya.
unsafe impl<const N: usize> bpf_common::aya::Pod for CharArray<N> {}

#[derive(thiserror::Error, Debug)]
pub enum MapKeyError {
    #[error("key coming from string must be ascii")]
    NotAscii,
    #[error("key must be smaller than {MAX_IMAGE_LEN}")]
    TooLong,
}

impl<const N: usize> TryFrom<Vec<u8>> for CharArray<N> {
    type Error = MapKeyError;

    fn try_from(mut data: Vec<u8>) -> Result<Self, Self::Error> {
        if data.len() > N {
            return Err(MapKeyError::TooLong);
        }
        data.resize(N, 0);
        let mut image_array = [0; N];
        image_array.clone_from_slice(&data[..]);
        Ok(Self(image_array))
    }
}

impl<const N: usize> FromStr for CharArray<N> {
    type Err = MapKeyError;

    fn from_str(image: &str) -> Result<Self, Self::Err> {
        if !image.is_ascii() {
            Err(MapKeyError::NotAscii)
        } else if image.len() >= N {
            Err(MapKeyError::TooLong)
        } else {
            let data: Vec<u8> = image.bytes().collect();
            Self::try_from(data)
        }
    }
}

impl<const N: usize> fmt::Display for CharArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.into_iter().take_while(|c| *c != 0) {
            write!(f, "{}", c as char)?;
        }
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for CharArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Image").field(&self.to_string()).finish()
    }
}
