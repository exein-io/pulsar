use std::path::PathBuf;

use which::which;

/// Resolve full path of the requested command
pub fn find_executable(cmd: &str) -> PathBuf {
    which(cmd).unwrap()
}
