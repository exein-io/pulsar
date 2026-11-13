//! The kernel's boot clock in wall-clock time.

use std::time::{Duration, SystemTime};

use nix::time::{ClockId, clock_gettime};

/// Converts nanoseconds of CLOCK_BOOTTIME (`bpf_ktime_get_boot_ns`,
/// `task->start_boottime`) to wall-clock time.
pub fn boot_to_system(boot_ns: u64) -> SystemTime {
    let now = SystemTime::now();
    let Ok(boot_now) = clock_gettime(ClockId::CLOCK_BOOTTIME) else {
        return now;
    };
    let boot_now = boot_now.tv_sec() as u64 * 1_000_000_000 + boot_now.tv_nsec() as u64;
    if boot_ns <= boot_now {
        now - Duration::from_nanos(boot_now - boot_ns)
    } else {
        now + Duration::from_nanos(boot_ns - boot_now)
    }
}
