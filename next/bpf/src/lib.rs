//! Pulsar's kernel side: every probe, the C SDK in `include/pulsar/` and the
//! record ABI shared with userspace.
//!
//! Probes write records into one shared ring buffer (`include/pulsar/ring.bpf.h`);
//! their layout is defined once, in `include/pulsar/abi.h` and
//! `include/pulsar/abi/*.h`, and [`abi`] is generated from it.
//!
//! Userspace side: [`loader::Loader`] loads probes into the ring,
//! [`ring::Ring`] reads it in order, [`record::RecordView`] checks a record
//! and the producer's module (e.g. [`process`]) decodes it.

pub mod loader;
pub mod process;
pub mod record;
pub mod ring;

use std::fmt;

pub use bpf_features::BpfFeatures;

/// Identifies the object a record comes from. Assigned by
/// [`loader::Loader::load`], always below `PULSAR_PRODUCER_MAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProducerId(pub u32);

impl fmt::Display for ProducerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Record types and constants generated from `include/pulsar/abi.h` and
/// `include/pulsar/abi/*.h`.
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
pub mod abi {
    include!(concat!(env!("OUT_DIR"), "/abi.rs"));
}

/// Compiled probes, one object per set of kernel features.
pub mod objects {
    use super::BpfFeatures;

    pub static PROCESS: &[(BpfFeatures, &[u8])] =
        &include!(concat!(env!("OUT_DIR"), "/process_objects.rs"));

    /// The variant of `probe` built for `features`.
    pub fn select(
        probe: &[(BpfFeatures, &'static [u8])],
        features: &BpfFeatures,
    ) -> Option<&'static [u8]> {
        probe
            .iter()
            .find(|(built_for, _)| built_for == features)
            .map(|(_, object)| *object)
    }
}
