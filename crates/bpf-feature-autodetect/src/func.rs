use aya_ebpf_bindings::bindings::BPF_REG_0;
use aya_obj::generated::bpf_insn;
use log::warn;

use super::{load_program, BpfProgType};
use crate::insn;

/// eBPF program bytecode with a simple function call (with `bpf_emit_call`
/// instruction) to the function with the given ID.
fn bpf_prog_func_id(func_id: u32) -> Vec<bpf_insn> {
    vec![
        insn::bpf_emit_call(func_id),
        insn::bpf_mov64_imm(BPF_REG_0 as u8, 0),
        insn::bpf_exit_insn(),
    ]
}

/// Checks whether the provided `func_id` for the given `prog_type` is
/// supported by the current kernel, by loading a minimal program trying to use
/// it.
///
/// Similar checks are performed by [`bpftool`].
///
/// [`bpftool`]: https://github.com/torvalds/linux/blob/v6.8/tools/bpf/bpftool/feature.c#L534-L544
pub fn func_id_supported(func_name: &str, func_id: u32, prog_type: BpfProgType) -> bool {
    let insns = bpf_prog_func_id(func_id);
    let res = load_program(prog_type, insns.as_slice(), &[]);
    match res {
        Ok(_) => true,
        Err(err) => {
            let err_msg = format!(
                "Function `{func_name}` ({func_id}) not supported in program type {prog_type:?}"
            );

            if let Ok(true) = std::env::var("RUST_BACKTRACE").map(|s| s == "1") {
                warn!("{err_msg}: {err}");
            } else {
                warn!("{err_msg}");
            }

            false
        }
    }
}
