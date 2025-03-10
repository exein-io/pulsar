//! eBPF assembly instructions.
//!
//! The purpose of this module is to allow to write minimal eBPF programs where
//! it's more convenient than writing them in C or Rust. Example: eBPF feature
//! probes.

use aya_ebpf_bindings::bindings::{
    BPF_ALU64, BPF_ATOMIC, BPF_CALL, BPF_EXIT, BPF_JMP, BPF_K, BPF_LDX, BPF_MEM, BPF_MOV, BPF_ST,
    BPF_STX, bpf_func_id,
};
use aya_obj::generated::bpf_insn;

pub fn bpf_atomic_op(size: u8, op: u32, dst_reg: u8, src_reg: u8, off: i16) -> bpf_insn {
    bpf_insn {
        code: BPF_STX as u8 | bpf_size(size) | BPF_ATOMIC as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst_reg, src_reg),
        off,
        imm: op as i32,
    }
}

pub fn bpf_emit_call(func_id: u32) -> bpf_insn {
    bpf_insn {
        code: BPF_JMP as u8 | BPF_CALL as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
        off: 0,
        imm: (func_id - bpf_func_id::BPF_FUNC_unspec) as i32,
    }
}

pub fn bpf_exit_insn() -> bpf_insn {
    bpf_insn {
        code: BPF_JMP as u8 | BPF_EXIT as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(0, 0),
        off: 0,
        imm: 0,
    }
}

pub fn bpf_jmp_imm(op: u8, dst_reg: u8, imm: i32, off: i16) -> bpf_insn {
    bpf_insn {
        code: BPF_JMP as u8 | bpf_op(op) | BPF_K as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst_reg, 0),
        off,
        imm,
    }
}

/// Memory load.
pub fn bpf_ldx_mem(size: u8, dst_reg: u8, src_reg: u8, off: i16) -> bpf_insn {
    bpf_insn {
        code: BPF_LDX as u8 | bpf_size(size) | BPF_MEM as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst_reg, src_reg),
        off,
        imm: 0,
    }
}

pub fn bpf_mov64_imm(dst_reg: u8, imm: i32) -> bpf_insn {
    bpf_insn {
        code: BPF_ALU64 as u8 | BPF_MOV as u8 | BPF_K as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst_reg, 0),
        off: 0,
        imm,
    }
}

pub fn bpf_op(code: u8) -> u8 {
    code & 0xf0
}

pub fn bpf_size(code: u8) -> u8 {
    code & 0x18
}

/// Memory store.
pub fn bpf_st_mem(size: u8, dst_reg: u8, off: i16, imm: i32) -> bpf_insn {
    bpf_insn {
        code: BPF_ST as u8 | bpf_size(size) | BPF_MEM as u8,
        _bitfield_align_1: [],
        _bitfield_1: bpf_insn::new_bitfield_1(dst_reg, 0),
        off,
        imm,
    }
}
