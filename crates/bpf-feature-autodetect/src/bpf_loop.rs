use aya::{include_bytes_aligned, programs::TracePoint, Bpf, BpfError};
use log::warn;

fn load_probe() -> Result<(), BpfError> {
    let mut bpf = Bpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/test_bpf_loop.none.bpf.o"
    )))?;
    let program: &mut TracePoint = bpf.program_mut("probe_bpf_loop").unwrap().try_into()?;
    program.load()?;
    Ok(())
}

pub fn bpf_loop_supported() -> bool {
    match load_probe() {
        Ok(_) => true,
        Err(e) => {
            let err_msg = "`bpf_loop` helper is not supported by the kernel";

            if let Ok(true) = std::env::var("RUST_BACKTRACE").map(|s| s == "1") {
                warn!("{err_msg}: {e}");
            } else {
                warn!("{err_msg}");
            }

            false
        }
    }
}
