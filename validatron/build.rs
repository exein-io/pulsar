extern crate lalrpop;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    lalrpop::process_root()?;

    Ok(())
}
