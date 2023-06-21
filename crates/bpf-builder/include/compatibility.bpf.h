#pragma once

// This file contains a list of kernel-version dependant features which must be
// specified at **compile-time**.
//
// CORE allows eBPF programs to conditionally enable some features by checking
// LINUX_KERNEL_VERSION (See loop.bpf.h for example usage). This allows to run
// particular versions of the code depending on the kernel, while keeping a
// single executable. Unfortunately, the particular features defined in this
// file will cause the verifier to reject the program at an earlier stage than
// dead code elimination, so that CORE feature won't work.
// For this reason we have to compile multiple versions of the pulsar probes.
// Currently we have two version, one for kernel 5.5 to 5.13 and one for 5.13 to
// mainline
//
//
// ## FEATURE_FN_POINTERS (since 5.13)
//
// Before kernel 5.13, taking the address of a static function would result
// in a verifier error.
// This feature is used in bpf_loop (see loop.bpf.h). While bpf_loop itself
// works only on kernel 5.17 or later, it's ok if it gets dead-code eliminated
// at load time. Unfortunately until kernel 5.13 this won't work, as the kernel
// will reject the program on an earlier stage.
//
// Check these links for more details:
// https://github.com/Exein-io/pulsar/issues/158
// https://github.com/torvalds/linux/commit/69c087ba6225b574afb6e505b72cb75242a3d844
//
//
// ## FEATURE_ATOMICS (since 5.12)
//
// Kernel 5.12 introduced support for atomic operations like
// __sync_fetch_and_add, __sync_fetch_and_sub etc.
//

#ifdef VERSION_5_13

#define FEATURE_ATOMICS
#define FEATURE_FN_POINTERS

#else

// Pulsar minimum supported kernel version is 5.5

#endif
