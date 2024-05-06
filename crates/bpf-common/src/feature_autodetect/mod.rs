//! This module checks what features are supported by the running kernel.

use std::mem;

use aya::{Btf, BtfError};
use aya_ebpf_bindings::bindings::bpf_attach_type::BPF_LSM_MAC;
pub use aya_obj::generated::bpf_prog_type as BpfProgType;
use aya_obj::{
    btf::BtfKind,
    generated::{bpf_attr, bpf_cmd, bpf_insn},
};
use libc::SYS_bpf;
use thiserror::Error;

pub mod atomic;
pub mod func;
pub mod kernel_version;
pub mod lsm;

/// Size of the eBPF verifier log.
const LOG_SIZE: usize = 4096;

#[derive(Debug, Error)]
pub enum FeatureProbeError {
    #[error("Failed to load the eBPF feature probe: {0}")]
    Load(String),
    #[error(transparent)]
    Btf(#[from] BtfError),
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

    if prog_type == BpfProgType::BPF_PROG_TYPE_LSM {
        // LSM programs need to be attached to any LSM hook. For feature probes
        // it doesn't matter which one. `task_alloc` is the most common one.
        let btf = Btf::from_sys_fs()?;
        let type_name = format!("bpf_lsm_task_alloc");
        u.attach_btf_id = btf.id_by_type_name_kind(type_name.as_str(), BtfKind::Func)?;

        u.expected_attach_type = BPF_LSM_MAC;
    }

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

#[cfg(feature = "test-suite")]
pub mod test_suite {
    use crate::test_runner::{TestCase, TestReport, TestSuite};

    use super::lsm::lsm_supported;

    pub fn tests() -> TestSuite {
        TestSuite {
            name: "feature_autodetect",
            tests: vec![lsm()],
        }
    }

    fn lsm() -> TestCase {
        TestCase::new("lsm", async {
            TestReport {
                success: tokio::task::spawn_blocking(lsm_supported).await.unwrap(),
                lines: vec![],
            }
        })
    }
}
