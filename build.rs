use anyhow::Result;
use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<()> {
    let gitcl = GitclBuilder::all_git()?;
    Emitter::default().add_instructions(&gitcl)?.emit()?;

    Ok(())
}
