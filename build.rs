use anyhow::Result;
use vergen_gitcl::{Emitter, Gitcl};

fn main() -> Result<()> {
    // Watch the sources so that unstaged edits flip `VERGEN_GIT_DIRTY`. Not the
    // package root: that recurses into `target`, which every build writes to,
    // so the build script would invalidate itself on each run.
    for path in ["src", "crates", "Cargo.toml", "Cargo.lock"] {
        println!("cargo:rerun-if-changed={path}");
    }

    let gitcl = Gitcl::all_git();
    Emitter::default().add_instructions(&gitcl)?.emit()?;

    Ok(())
}
