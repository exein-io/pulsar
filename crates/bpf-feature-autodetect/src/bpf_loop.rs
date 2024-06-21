use aya_ebpf_bindings::bindings::{
    bpf_func_id, BPF_DW, BPF_IMM, BPF_JA, BPF_JEQ, BPF_LD, BPF_MOV, BPF_PSEUDO_FUNC, BPF_REG_0,
    BPF_REG_1, BPF_REG_2, BPF_REG_3, BPF_REG_4,
};
use aya_obj::generated::{bpf_func_info, bpf_insn};
use log::warn;

use super::{load_program, BpfProgType};
use crate::insn;

/// eBPF program bytecode with simple `bpf_loop` call.
fn bpf_prog_loop() -> Vec<bpf_insn> {
    vec![
        // Main
        insn::bpf_emit_call(bpf_func_id::BPF_FUNC_jiffies64),
        insn::bpf_jmp_imm(BPF_JEQ as u8, BPF_REG_0 as u8, 777, 2),
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_1 as u8, 1),
        insn::bpf_jmp_imm(BPF_JA as u8, 0, 0, 1),
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_1 as u8, 2),
        insn::bpf_raw_insn(
            BPF_LD as u8 | BPF_IMM as u8 | BPF_DW as u8,
            BPF_REG_2 as u8,
            BPF_PSEUDO_FUNC as u8,
            0,
            6,
        ),
        insn::bpf_raw_insn(0, 0, 0, 0, 0),
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_3 as u8, 0),
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_4 as u8, 0),
        insn::bpf_emit_call(bpf_func_id::BPF_FUNC_loop),
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_0 as u8, 0),
        insn::bpf_exit_insn(),
        // Callback
        insn::bpf_alu64_imm(BPF_MOV as u8, BPF_REG_0 as u8, 1),
        insn::bpf_exit_insn(),
    ]
}

/// Checks whether the current kernel supports `bpf_loop` helper.
pub fn bpf_loop_supported() -> bool {
    let insns = bpf_prog_loop();

    let fn_info: &[bpf_func_info] = &[
        bpf_func_info {
            insn_off: 0,
            type_id: 6,
        },
        bpf_func_info {
            insn_off: 12,
            type_id: 7,
        },
    ];

    // Program type doesn't matter, kprobe is just the most basic one.
    let res = load_program(BpfProgType::BPF_PROG_TYPE_KPROBE, insns.as_slice(), fn_info);
    match res {
        Ok(_) => true,
        Err(e) => {
            warn!("`bpf_loop` helper is not supported by the kernel: {e}");
            false
        }
    }
}
