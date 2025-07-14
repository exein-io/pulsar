use std::sync::OnceLock;

/// Build the version string shown by clap for the pulsar binaries.
///
/// This helper is intended to be used only by the two binaries and is kept
/// under `src/bin/_common` so it doesn't leak into the library API surface.
/// In each binary, import this module (for example with:
/// `mod _common; use _common::clap_version;`) and then reference it in the
/// clap attribute as:
/// `#[clap(version = clap_version::pulsar_clap_version())]`.
pub(crate) fn pulsar_clap_version() -> &'static str {
    // clap requires a &'static str, so we cache the computed String here.
    static CLAP_VERSION: OnceLock<String> = OnceLock::new();

    CLAP_VERSION.get_or_init(|| {
        #[cfg(debug_assertions)]
        const PROFILE: &str = "debug";
        #[cfg(not(debug_assertions))]
        const PROFILE: &str = "release";

        // `env!("VERGEN_GIT_DIRTY")` is either "true" or "false".
        // We can’t use == in a const, but we can look at the length (4 vs 5).
        const GIT_DIRTY: bool = env!("VERGEN_GIT_DIRTY").len() == 4;

        const DIRTY_SUFFIX: &str = if GIT_DIRTY { "+dirty" } else { "" };

        format!(
            r#"{}
commit: {}{}
profile: {PROFILE}"#,
            pulsar::metadata::VERSION,
            pulsar::metadata::GIT_SHA,
            DIRTY_SUFFIX
        )
    })
}
