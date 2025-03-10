use std::{collections::HashMap, hash::Hash};

pub use aya_obj::generated::bpf_prog_type as BpfProgType;
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BpfFeatures {
    pub atomics: bool,
    pub cgroup_skb_task_btf: bool,
    pub bpf_loop: bool,
    pub lsm: bool,
}

impl BpfFeatures {
    pub fn bpf_objfile_suffix(&self) -> String {
        let mut feature_codes = String::new();

        if self.atomics {
            feature_codes.push('a');
        }
        if self.cgroup_skb_task_btf {
            feature_codes.push('c');
        }
        if self.bpf_loop {
            feature_codes.push('l');
        }
        if self.lsm {
            feature_codes.push('s');
        }

        if feature_codes.is_empty() {
            feature_codes.push_str("none");
        }

        format!("{}.bpf.o", feature_codes)
    }

    pub fn build_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if self.atomics {
            args.push("-DFEATURE_ATOMICS".to_string());
        }
        if self.cgroup_skb_task_btf {
            args.push("-DFEATURE_CGROUP_TASK_BTF".to_string());
        }
        if self.bpf_loop {
            args.push("-DFEATURE_BPF_LOOP".to_string());
        }
        if self.lsm {
            args.push("-DFEATURE_LSM".to_string());
        }

        args
    }

    pub fn all_combinations() -> HashMap<Self, (String, Vec<String>)> {
        let mut combinations = HashMap::new();

        for atomics in [true, false] {
            for cgroup_skb_task_btf in [true, false] {
                for bpf_loop in [true, false] {
                    for lsm in [true, false] {
                        let features = Self {
                            atomics,
                            cgroup_skb_task_btf,
                            bpf_loop,
                            lsm,
                        };
                        combinations.insert(
                            features.clone(),
                            (features.bpf_objfile_suffix(), features.build_args()),
                        );
                    }
                }
            }
        }

        combinations
    }
}

impl ToTokens for BpfFeatures {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let atomics = self.atomics;
        let cgroup_skb_task_btf = self.cgroup_skb_task_btf;
        let bpf_loop = self.bpf_loop;
        let lsm = self.lsm;

        let generated = quote! {
            BpfFeatures {
                atomics: #atomics,
                cgroup_skb_task_btf: #cgroup_skb_task_btf,
                bpf_loop: #bpf_loop,
                lsm: #lsm,
            }
        };

        generated.to_tokens(tokens);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bpf_features() {
        let features = BpfFeatures {
            atomics: false,
            cgroup_skb_task_btf: false,
            bpf_loop: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "none.bpf.o");
        assert!(features.build_args().is_empty());

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: false,
            bpf_loop: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "a.bpf.o");
        assert_eq!(features.build_args().as_slice(), &["-DFEATURE_ATOMICS"]);

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: true,
            bpf_loop: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "ac.bpf.o");
        assert_eq!(
            features.build_args().as_slice(),
            &["-DFEATURE_ATOMICS", "-DFEATURE_CGROUP_TASK_BTF"]
        );

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: true,
            bpf_loop: true,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "acl.bpf.o");
        assert_eq!(
            features.build_args().as_slice(),
            &[
                "-DFEATURE_ATOMICS",
                "-DFEATURE_CGROUP_TASK_BTF",
                "-DFEATURE_BPF_LOOP"
            ]
        );

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: true,
            bpf_loop: true,
            lsm: true,
        };
        assert_eq!(features.bpf_objfile_suffix(), "acls.bpf.o");
        assert_eq!(
            features.build_args(),
            &[
                "-DFEATURE_ATOMICS",
                "-DFEATURE_CGROUP_TASK_BTF",
                "-DFEATURE_BPF_LOOP",
                "-DFEATURE_LSM"
            ]
        );

        let features = BpfFeatures {
            atomics: false,
            cgroup_skb_task_btf: true,
            bpf_loop: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "c.bpf.o");
        assert_eq!(features.build_args(), &["-DFEATURE_CGROUP_TASK_BTF"]);
    }
}
