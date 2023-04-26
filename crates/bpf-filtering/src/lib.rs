//! # Events filtering
//!
//! This module contains the logic for implementing event filtering:
//! deciding wether an event is interesting for the rest of the system
//! or if it should be discarded.
//!
//! # Policy system requirements
//!
//! - Filtering should always happen on kernel side (for performance and consistency)
//! - Support for global monitoring (for lightweight probes scenarios like process/fs/network monitor)
//! - Support for very specific monitoring (for heavy probes scenarios like process anomaly/syscall monitor)
//! - Allow whitelist of uninteresting processes
//! - Allow specification of multiple targets
//!
//! # General design
//!
//! We allow user to specify:
//! - Targets: a list of processes we're interested in
//!   - each target is either a Pid or an Image (the executable path)
//!     - Pid targets are checked only on startup
//!   - specifies if we should consider its children as targets as well
//! - Whitelist: a list of processes we're not interested in
//!   - always specified with Image
//!   - specifies if we should consider its children as whitelist as well
//!
//! By default everything is interesting.
//! We do filtering based on process id, we ignore thread id.
//!
//! # Implementation
//!
//! Filtering must be done on kernel side, so we need several maps:
//!
//! **`(pinned) interesting: HashMap<Pid, struct { interesting: bool, children_interesting: bool}>`**
//! - Contains all processes and weather we should generate events for them or their children.
//! - It's initialized by userspace on startup by checking `procfs`
//! - It's updated by `process_monitor` on fork/exec/exit events
//!   - on fork we set `interesting[child pid] = interesting[parent pid].children_interesting`
//! - It's consulted by every other probe before executing
//!
//! **`rules: HasMap<Image, (track: bool, extend_to_children: bool)>`**
//! - Contains the target/whitelist images and weather the rule extends to children
//! - Generated and updated by userspace.
//! - It's consulted by `process_monitor` on `exec` to check if we should update something
//!   - If exec image is in target/whitelist we set `interesting[my pid].interesting = track`
//!   - if exec image is in target/whitelist and extended to children, we set `interesting[my pid].children_interesting = track`
//!
//! ## Startup procedure
//!
//! We empty the `interesting` map.
//! We should check `procfs` and build a tree of all interesting.
//! We build the `interesting` map by starting from pid 0 and applying recursively the choices above by checking the process `/proc/{}/exe`.

pub(crate) mod config;
pub(crate) mod initializer;
pub(crate) mod maps;
pub(crate) mod process_tree;
#[cfg(feature = "test-suite")]
pub mod test_suite;
