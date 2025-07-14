use anyhow::Result;
use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=.git/index"); // staged <-> clean
    println!("cargo:rerun-if-changed=.git/packed-refs"); // packed commits
    println!("cargo:rerun-if-changed=."); // unstaged edits

    let gitcl = GitclBuilder::all_git()?;
    Emitter::default().add_instructions(&gitcl)?.emit()?;

    Ok(())
}
