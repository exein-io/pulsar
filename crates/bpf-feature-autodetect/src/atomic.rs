use aya_ebpf_bindings::bindings::{BPF_DW, BPF_JEQ, BPF_REG_0, BPF_REG_1, BPF_REG_10, BPF_XCHG};
use aya_obj::generated::bpf_insn;
use log::warn;

use super::{load_program, BpfProgType};
use crate::insn;

/// eBPF program bytecode with simple atomic operations.
fn bpf_prog_atomic() -> Vec<bpf_insn> {
    vec![
        // val = 3;
        insn::bpf_st_mem(BPF_DW as u8, BPF_REG_10 as u8, -8, 3),
        // old = atomic_xchg(&val, 4);
        insn::bpf_mov64_imm(BPF_REG_1 as u8, 4),
        insn::bpf_atomic_op(
            BPF_DW as u8,
            BPF_XCHG,
            BPF_REG_10 as u8,
            BPF_REG_1 as u8,
            -8,
        ),
        // if (old != 3) exit(1);
        insn::bpf_jmp_imm(BPF_JEQ as u8, BPF_REG_1 as u8, 3, 2),
        insn::bpf_mov64_imm(BPF_REG_0 as u8, 1),
        insn::bpf_exit_insn(),
        // if (val != 4) exit(2);
        insn::bpf_ldx_mem(BPF_DW as u8, BPF_REG_0 as u8, BPF_REG_10 as u8, -8),
        insn::bpf_jmp_imm(BPF_JEQ as u8, BPF_REG_0 as u8, 4, 2),
        insn::bpf_mov64_imm(BPF_REG_0 as u8, 2),
        insn::bpf_exit_insn(),
        // exit(0);
        insn::bpf_mov64_imm(BPF_REG_0 as u8, 0),
        insn::bpf_exit_insn(),
    ]
}

/// Checks whether the current kernel supports atomic operations in eBPF.
pub fn atomics_supported() -> bool {
    let insns = bpf_prog_atomic();
    // Program type doesn't matter, kprobe is just the most basic one.
    let res = load_program(BpfProgType::BPF_PROG_TYPE_KPROBE, insns.as_slice(), &[]);
    match res {
        Ok(_) => true,
        Err(e) => {
            warn!("Atomic operations in eBPF are not supported by the kernel: {e}");
            false
        }
    }
}
