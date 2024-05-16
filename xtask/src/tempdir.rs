use std::{
    env,
    ffi::{OsStr, OsString},
    fs::{self, create_dir},
    io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// A temporary directory which is cleaned on `drop` (unless the `preserve` field
/// is `true`.
pub struct TempDir {
    /// Path to the temp directory.
    dir_path: PathBuf,
    /// Whether to preserve the temp  directory after `drop`. If `false`, it
    /// gets removed automatically.
    preserve: bool,
}

impl TempDir {
    pub fn new(prefix: &str, preserve: bool) -> io::Result<Self> {
        let dir_path = env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
        create_dir(dir_path.as_path())?;
        Ok(Self { dir_path, preserve })
    }

    // We don't want to move the whole `TempDir` here and it's totally fine to
    // take a reference just to clone a field.
    #[allow(clippy::wrong_self_convention)]
    pub fn into_os_string(&self) -> OsString {
        self.dir_path.clone().into_os_string()
    }

    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        self.dir_path.join(path)
    }
}

impl AsRef<OsStr> for TempDir {
    fn as_ref(&self) -> &OsStr {
        self.dir_path.as_os_str()
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        self.dir_path.as_path()
    }
}

impl Drop for TempDir {
    /// Removes the temp  directory if requested.
    fn drop(&mut self) {
        if !self.preserve && self.dir_path.exists() {
            let _ = fs::remove_dir_all(&self.dir_path);
        }
    }
}
