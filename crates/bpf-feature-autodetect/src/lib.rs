//! This module checks what features are supported by the running kernel.

use std::mem;

use aya_ebpf_bindings::bindings::bpf_func_id;
pub use aya_obj::generated::bpf_prog_type as BpfProgType;
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_insn};
use bpf_features::BpfFeatures;
use libc::SYS_bpf;
use thiserror::Error;

pub mod atomic;
pub mod func;
pub mod insn;
pub mod kernel_version;
pub mod lsm;

use crate::{atomic::atomics_supported, func::func_id_supported, lsm::lsm_supported};

/// Size of the eBPF verifier log.
const LOG_SIZE: usize = 4096;

#[derive(Debug, Error)]
pub enum FeatureProbeError {
    #[error("Failed to load the eBPF feature probe: {0}")]
    Load(String),
}

pub fn autodetect_features() -> BpfFeatures {
    BpfFeatures {
        atomics: atomics_supported(),
        cgroup_skb_task_btf: func_id_supported(
            bpf_func_id::BPF_FUNC_get_current_task_btf,
            BpfProgType::BPF_PROG_TYPE_CGROUP_SKB,
        ),
        bpf_loop: func_id_supported(
            bpf_func_id::BPF_FUNC_loop,
            // Program type doesn't matter here.
            BpfProgType::BPF_PROG_TYPE_KPROBE,
        ),
        lsm: lsm_supported(),
    }
}

/// Loads the given eBPF bytecode to the kernel.
pub(crate) fn load_program(
    prog_type: BpfProgType,
    insns: Vec<bpf_insn>,
) -> Result<(), FeatureProbeError> {
    let mut attr = unsafe { mem::zeroed::<bpf_attr>() };
    let u = unsafe { &mut attr.__bindgen_anon_3 };

    let gpl = b"GPL\0";
    u.license = gpl.as_ptr() as u64;

    u.insn_cnt = insns.len() as u32;
    u.insns = insns.as_ptr() as u64;
    u.prog_type = prog_type as u32;

    let mut log = vec![0u8; LOG_SIZE];
    u.log_level = 1;
    u.log_buf = log.as_mut_ptr() as u64;
    u.log_size = LOG_SIZE as u32;

    let ret = unsafe {
        libc::syscall(
            SYS_bpf,
            bpf_cmd::BPF_PROG_LOAD,
            &mut attr,
            mem::size_of::<bpf_attr>(),
        )
    };

    if ret >= 0 {
        Ok(())
    } else {
        // Truncate the verifier log.
        if let Some(index) = log.iter().position(|&x| x == 0) {
            log.truncate(index);
        }

        Err(FeatureProbeError::Load(
            String::from_utf8_lossy(log.as_slice()).to_string(),
        ))
    }
}
