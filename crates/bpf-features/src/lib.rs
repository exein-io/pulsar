use std::{collections::HashMap, hash::Hash};

pub use aya_obj::generated::bpf_prog_type as BpfProgType;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BpfFeatures {
    pub atomics: bool,
    pub cgroup_skb_task_btf: bool,
    pub fn_pointers: bool,
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
        if self.fn_pointers {
            feature_codes.push('f');
        }
        if self.lsm {
            feature_codes.push('l');
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
        if self.fn_pointers {
            args.push("-DFEATURE_FN_POINTERS".to_string());
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
                for fn_pointers in [true, false] {
                    for lsm in [true, false] {
                        let features = Self {
                            atomics,
                            cgroup_skb_task_btf,
                            fn_pointers,
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
        let fn_pointers = self.fn_pointers;
        let lsm = self.lsm;

        let generated = quote! {
            BpfFeatures {
                atomics: #atomics,
                cgroup_skb_task_btf: #cgroup_skb_task_btf,
                fn_pointers: #fn_pointers,
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
            fn_pointers: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "none.bpf.o");
        assert!(features.build_args().is_empty());

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: false,
            fn_pointers: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "a.bpf.o");
        assert_eq!(features.build_args().as_slice(), &["-DFEATURE_ATOMICS"]);

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: true,
            fn_pointers: false,
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
            fn_pointers: true,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "acf.bpf.o");
        assert_eq!(
            features.build_args().as_slice(),
            &[
                "-DFEATURE_ATOMICS",
                "-DFEATURE_CGROUP_TASK_BTF",
                "-DFEATURE_FN_POINTERS"
            ]
        );

        let features = BpfFeatures {
            atomics: true,
            cgroup_skb_task_btf: true,
            fn_pointers: true,
            lsm: true,
        };
        assert_eq!(features.bpf_objfile_suffix(), "acfl.bpf.o");
        assert_eq!(
            features.build_args(),
            &[
                "-DFEATURE_ATOMICS",
                "-DFEATURE_CGROUP_TASK_BTF",
                "-DFEATURE_FN_POINTERS",
                "-DFEATURE_LSM"
            ]
        );

        let features = BpfFeatures {
            atomics: false,
            cgroup_skb_task_btf: true,
            fn_pointers: false,
            lsm: false,
        };
        assert_eq!(features.bpf_objfile_suffix(), "c.bpf.o");
        assert_eq!(features.build_args(), &["-DFEATURE_CGROUP_TASK_BTF"]);
    }
}
