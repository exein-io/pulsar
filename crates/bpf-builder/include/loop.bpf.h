#pragma once

// The LOOP macro allows to iterate using the `bpf_loop` helper function when
// available (kernel >= 5.17) and falls back on a regular loop when the kernel
// is too old.
//
// The macro takes:
// - the maximum number of iterations
// - a callback function, which will be called until it returns 1.
// - a pointer which will be passed to the context, which can be used to keep
//   state across iterations.

// Note: callback_fn must be declared as `static __always_inline` to satisfy the
// verifier. For some reason, having this double call to the same non-inline
// function seems to cause issues.
#ifdef FEATURE_NO_FN_POINTERS
// On kernel <= 5.13 taking the address of a function results in a verifier
// error, even if inside a dead-code elimination branch.
#define LOOP(max_iterations, max_unroll, callback_fn, ctx)                     \
  _Pragma("unroll") for (int i = 0; i < 10; i++) {                             \
    if (callback_fn(i, ctx) == LOOP_STOP)                                      \
      break;                                                                   \
  }
#else
#define LOOP(max_iterations, max_unroll, callback_fn, ctx)                     \
  if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 17, 0)) {                      \
    bpf_loop(max_iterations, callback_fn, ctx, 0);                             \
  } else {                                                                     \
    _Pragma("unroll") for (int i = 0; i < max_unroll; i++) {                   \
      if (callback_fn(i, ctx) == LOOP_STOP)                                    \
        break;                                                                 \
    }                                                                          \
  }
#endif

#define LOOP_CONTINUE 0
#define LOOP_STOP 1
