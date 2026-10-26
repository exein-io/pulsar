/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

// eBPF side of aya-log: log records are written to the AYA_LOGS ring buffer and
// decoded in userspace by aya_log::EbpfLogger (aya-log 0.3, aya-log-common
// 0.2).
//
// Usage
// -----
// Every macro argument is one piece of the message, printed in order:
//
//   AYA_LOG_ERROR("offset out of bounds: ", offset, "+", len);
//   AYA_LOG_DEBUG("flags: ", LOG_FMT_HEX(flags));
//   AYA_LOG_INFO("container id: ", LOG_FMT_STR(buf));
//
// - String literals and integers are passed directly. The integer encoding is
//   picked from the C type.
// - Everything else is wrapped in a LOG_FMT_* helper (hex, bytes, IP and MAC
//   addresses, pointers, runtime strings).
// - A runtime string (LOG_FMT_STR, LOG_FMT_USTR) may only be the last argument.
//   Passing a char pointer or array directly is a compile error.
// - At most 16 arguments.
// - A message is only built when its level is enabled by AYA_LOG_LEVEL, which
//   userspace sets before load (aya_log::LEVEL). The default 0 disables
//   logging, and the verifier removes the disabled calls as dead code.
//
// Wire format (aya-log-common 0.2, all integers native-endian)
// -------------------------------------------------------------
//   record = [u16 record length, including these 2 bytes]
//            [header fields][arguments]
//   field  = [u8 tag][u16 value length][value]
//
// Header fields (tags from aya_log_record_field), each exactly once:
//   Target (string), Level (u8), Module (string), File (string), Line (u32),
//   NumArgs (u32). Target is left empty and set by the userspace logger.
//   Module carries the function name.
//
// Arguments (tags from aya_log_argument): NumArgs fields, concatenated in
// order by the decoder. A DisplayHint argument changes how the next value
// is printed (e.g. hex) and counts as an argument of its own.
//
// Layout and verifier
// -------------------
// Every argument except a trailing runtime string has a size known at compile
// time, so all offsets are constants. Together with the 8-byte aligned ring
// buffer reservation this lets clang use wide stores and gives the verifier
// constant bounds for every write. A runtime string in the middle would make
// all following offsets variable, which is why it must come last.

#include "vmlinux.h"

#include "bpf/bpf_helpers.h"

// The enums mirror aya-log-common 0.2. The decoder reads tags straight into
// Rust enums, so a value missing there is undefined behaviour, not an error.

enum aya_log_record_field {
  AYA_LOG_RF_Target = 0,
  AYA_LOG_RF_Level = 1,
  AYA_LOG_RF_Module = 2,
  AYA_LOG_RF_File = 3,
  AYA_LOG_RF_Line = 4,
  AYA_LOG_RF_NumArgs = 5,
};

enum aya_log_argument {
  AYA_LOG_ARG_DisplayHint = 0,
  AYA_LOG_ARG_I8 = 1,
  AYA_LOG_ARG_I16 = 2,
  AYA_LOG_ARG_I32 = 3,
  AYA_LOG_ARG_I64 = 4,
  AYA_LOG_ARG_Isize = 5,
  AYA_LOG_ARG_U8 = 6,
  AYA_LOG_ARG_U16 = 7,
  AYA_LOG_ARG_U32 = 8,
  AYA_LOG_ARG_U64 = 9,
  AYA_LOG_ARG_Usize = 10,
  AYA_LOG_ARG_F32 = 11,
  AYA_LOG_ARG_F64 = 12,
  AYA_LOG_ARG_Ipv4Addr = 13,
  AYA_LOG_ARG_Ipv6Addr = 14,
  AYA_LOG_ARG_ArrU8Len4 = 15,
  AYA_LOG_ARG_ArrU8Len6 = 16,
  AYA_LOG_ARG_ArrU8Len16 = 17,
  AYA_LOG_ARG_ArrU16Len8 = 18,
  AYA_LOG_ARG_Bytes = 19,
  AYA_LOG_ARG_Str = 20,
  AYA_LOG_ARG_Pointer = 21,
};

enum aya_log_display_hint {
  AYA_LOG_HINT_Default = 1,
  AYA_LOG_HINT_LowerHex = 2,
  AYA_LOG_HINT_UpperHex = 3,
  AYA_LOG_HINT_Ip = 4,
  AYA_LOG_HINT_LowerMac = 5,
  AYA_LOG_HINT_UpperMac = 6,
  AYA_LOG_HINT_Pointer = 7,
};

enum aya_log_level {
  AYA_LOG_LEVEL_Error = 1,
  AYA_LOG_LEVEL_Warn = 2,
  AYA_LOG_LEVEL_Info = 3,
  AYA_LOG_LEVEL_Debug = 4,
  AYA_LOG_LEVEL_Trace = 5,
};

// Bytes reserved for LOG_FMT_STR and LOG_FMT_USTR, including the NUL.
#define AYA_LOG_STR_DEFAULT_MAX 256

// Not pinned: every eBPF object has its own AYA_LOGS map.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 16 * 1024);
} AYA_LOGS SEC(".maps");

// Highest enabled aya_log_level, set by userspace before load.
const volatile __u8 AYA_LOG_LEVEL = 0;

// Sizes of the wire format building blocks. Every size used below, for the
// reservation and for the writes, is built from these.

// The u16 record length at the start of every record.
#define __AYA_LOG_PREFIX_SIZE sizeof(__u16)
// One field: u8 tag, u16 length, value of len bytes.
#define __AYA_LOG_FIELD_SIZE(len) (sizeof(__u8) + sizeof(__u16) + (len))
// A DisplayHint argument: one field holding a u8.
#define __AYA_LOG_HINT_SIZE __AYA_LOG_FIELD_SIZE(sizeof(__u8))

// Length of a string literal or __func__ without the NUL.
#define __AYA_LOG_STRLEN(s) (sizeof(s) - 1)

// Size of the length prefix plus all header fields. It is the same for all
// calls in one function, because only Module and File are variable and both
// are known at compile time.
#define __AYA_LOG_HEADER_SIZE                                                  \
  (__AYA_LOG_PREFIX_SIZE + __AYA_LOG_FIELD_SIZE(0) /* Target */ +              \
   __AYA_LOG_FIELD_SIZE(sizeof(__u8)) /* Level */ +                            \
   __AYA_LOG_FIELD_SIZE(__AYA_LOG_STRLEN(__func__)) /* Module */ +             \
   __AYA_LOG_FIELD_SIZE(__AYA_LOG_STRLEN(__FILE_NAME__)) /* File */ +          \
   __AYA_LOG_FIELD_SIZE(sizeof(__u32)) /* Line */ +                            \
   __AYA_LOG_FIELD_SIZE(sizeof(__u32)) /* NumArgs */)

// Formatting helpers
// ------------------
// Each LOG_FMT_* helper wraps a value in its own struct type. The struct type
// is what _Generic dispatches on below, and its fields carry what the writer
// needs (value, size, display hint).

struct aya_log_hex {
  __u64 v;
  __u8 size;
  __u8 hint;
};

struct aya_log_bytes {
  const void *p;
  __u16 n;
  __u8 hint;
};

struct aya_log_ip4 {
  __be32 v;
};

struct aya_log_ip6 {
  const void *p;
};

struct aya_log_mac {
  const void *p;
  __u8 hint;
};

struct aya_log_ptr {
  __u64 v;
};

struct aya_log_str {
  const void *p;
  __u16 max;
  bool user;
};

// Evaluates to n, but fails to compile if n is not a compile-time constant.
// Used for lengths, which must be constant to keep all sizes constant.
#define __AYA_LOG_CONST(n)                                                     \
  ({                                                                           \
    _Static_assert(__builtin_constant_p(n),                                    \
                   "length must be a compile-time constant");                  \
    (n);                                                                       \
  })

// Integer in lower or upper case hex, e.g. "ff". Printed with the width of x.
#define LOG_FMT_HEX(x)                                                         \
  ((struct aya_log_hex){(__u64)(x), sizeof(x), AYA_LOG_HINT_LowerHex})
#define LOG_FMT_UHEX(x)                                                        \
  ((struct aya_log_hex){(__u64)(x), sizeof(x), AYA_LOG_HINT_UpperHex})
// n bytes at p as hex, e.g. "deadbeef". n must be a constant.
#define LOG_FMT_HEX_BYTES(p, n)                                                \
  ((struct aya_log_bytes){(p), __AYA_LOG_CONST(n), AYA_LOG_HINT_LowerHex})
#define LOG_FMT_UHEX_BYTES(p, n)                                               \
  ((struct aya_log_bytes){(p), __AYA_LOG_CONST(n), AYA_LOG_HINT_UpperHex})
// IPv4 address in network byte order, e.g. "10.0.0.1".
#define LOG_FMT_IP4(be32) ((struct aya_log_ip4){(be32)})
// 16 bytes at p as an IPv6 address, e.g. "2001:db8::1".
#define LOG_FMT_IP6(p) ((struct aya_log_ip6){(p)})
// 6 bytes at p as a MAC address, e.g. "aa:bb:cc:01:02:03".
#define LOG_FMT_MAC(p) ((struct aya_log_mac){(p), AYA_LOG_HINT_LowerMac})
#define LOG_FMT_UMAC(p) ((struct aya_log_mac){(p), AYA_LOG_HINT_UpperMac})
// Pointer value, e.g. "0xffff8b7394f03240".
#define LOG_FMT_PTR(p) ((struct aya_log_ptr){(__u64)(p)})
// NUL-terminated string at p in kernel (STR) or user (USTR) memory, read with
// bpf_probe_read_{kernel,user}_str. At most n - 1 characters are printed.
// Only allowed as the last argument. n must be a constant.
#define LOG_FMT_STR_N(p, n)                                                    \
  ((struct aya_log_str){(p), __AYA_LOG_CONST(n), false})
#define LOG_FMT_USTR_N(p, n)                                                   \
  ((struct aya_log_str){(p), __AYA_LOG_CONST(n), true})
#define LOG_FMT_STR(p) LOG_FMT_STR_N(p, AYA_LOG_STR_DEFAULT_MAX)
#define LOG_FMT_USTR(p) LOG_FMT_USTR_N(p, AYA_LOG_STR_DEFAULT_MAX)

// Writers
// -------
// A writer serializes one argument at offset off of the record and returns the
// number of bytes written. There is one writer per argument type, selected by
// __AYA_LOG_WRITER. All writers share the signature
//   (rec, off, value, sz)
// where sz is sizeof() of the original macro argument, because _Generic picks
// the function and the call arguments must be the same for all of them. Only
// the literal writer needs sz: a literal decays to char * in the temporary,
// so its length is taken from the original argument.

// Writes one field (tag, length, value) and returns its size.
static __always_inline __u32 __aya_log_field(__u8 *rec, __u32 off, __u8 tag,
                                             const void *val, __u16 len) {
  __builtin_memcpy(rec + off, &tag, sizeof(tag));
  __builtin_memcpy(rec + off + sizeof(tag), &len, sizeof(len));
  __builtin_memcpy(rec + off + sizeof(tag) + sizeof(len), val, len);
  return __AYA_LOG_FIELD_SIZE(len);
}

// Writes a DisplayHint argument, which applies to the next value.
static __always_inline __u32 __aya_log_hint(__u8 *rec, __u32 off, __u8 hint) {
  return __aya_log_field(rec, off, AYA_LOG_ARG_DisplayHint, &hint,
                         sizeof(hint));
}

// Defines a writer for one integer type.
#define __AYA_LOG_INT_WRITER(name, type, tag)                                  \
  static __always_inline __u32 name(__u8 *rec, __u32 off, type v, __u32 sz) {  \
    return __aya_log_field(rec, off, tag, &v, sizeof(v));                      \
  }

__AYA_LOG_INT_WRITER(__aya_log_w_i8, __s8, AYA_LOG_ARG_I8)
__AYA_LOG_INT_WRITER(__aya_log_w_i16, __s16, AYA_LOG_ARG_I16)
__AYA_LOG_INT_WRITER(__aya_log_w_i32, __s32, AYA_LOG_ARG_I32)
__AYA_LOG_INT_WRITER(__aya_log_w_i64, __s64, AYA_LOG_ARG_I64)
__AYA_LOG_INT_WRITER(__aya_log_w_u8, __u8, AYA_LOG_ARG_U8)
__AYA_LOG_INT_WRITER(__aya_log_w_u16, __u16, AYA_LOG_ARG_U16)
__AYA_LOG_INT_WRITER(__aya_log_w_u32, __u32, AYA_LOG_ARG_U32)
__AYA_LOG_INT_WRITER(__aya_log_w_u64, __u64, AYA_LOG_ARG_U64)

static __always_inline __u32 __aya_log_w_lit(__u8 *rec, __u32 off,
                                             const char *s, __u32 sz) {
  return __aya_log_field(rec, off, AYA_LOG_ARG_Str, s, sz - 1);
}

// Hex is sent as the unsigned integer of the original width, so a negative
// value prints as its two's complement, like {:x} in Rust.
static __always_inline __u32 __aya_log_w_hex(__u8 *rec, __u32 off,
                                             struct aya_log_hex h, __u32 sz) {
  __u32 n = __aya_log_hint(rec, off, h.hint);
  switch (h.size) {
  case sizeof(__u8):
    return n + __aya_log_w_u8(rec, off + n, h.v, 0);
  case sizeof(__u16):
    return n + __aya_log_w_u16(rec, off + n, h.v, 0);
  case sizeof(__u32):
    return n + __aya_log_w_u32(rec, off + n, h.v, 0);
  default:
    return n + __aya_log_w_u64(rec, off + n, h.v, 0);
  }
}

static __always_inline __u32 __aya_log_w_bytes(__u8 *rec, __u32 off,
                                               struct aya_log_bytes b,
                                               __u32 sz) {
  __u32 n = __aya_log_hint(rec, off, b.hint);
  return n + __aya_log_field(rec, off + n, AYA_LOG_ARG_Bytes, b.p, b.n);
}

static __always_inline __u32 __aya_log_w_ip4(__u8 *rec, __u32 off,
                                             struct aya_log_ip4 a, __u32 sz) {
  return __aya_log_field(rec, off, AYA_LOG_ARG_Ipv4Addr, &a.v, sizeof(a.v));
}

static __always_inline __u32 __aya_log_w_ip6(__u8 *rec, __u32 off,
                                             struct aya_log_ip6 a, __u32 sz) {
  return __aya_log_field(rec, off, AYA_LOG_ARG_Ipv6Addr, a.p, 16);
}

static __always_inline __u32 __aya_log_w_mac(__u8 *rec, __u32 off,
                                             struct aya_log_mac m, __u32 sz) {
  __u32 n = __aya_log_hint(rec, off, m.hint);
  return n + __aya_log_field(rec, off + n, AYA_LOG_ARG_ArrU8Len6, m.p, 6);
}

static __always_inline __u32 __aya_log_w_ptr(__u8 *rec, __u32 off,
                                             struct aya_log_ptr p, __u32 sz) {
  __u32 n = __aya_log_hint(rec, off, AYA_LOG_HINT_Pointer);
  return n +
         __aya_log_field(rec, off + n, AYA_LOG_ARG_Pointer, &p.v, sizeof(p.v));
}

// The string is read straight into the record, after the tag and length, and
// the length is filled in afterwards. On a read error an empty string is sent.
static __always_inline __u32 __aya_log_w_str(__u8 *rec, __u32 off,
                                             struct aya_log_str s, __u32 sz) {
  __u8 tag = AYA_LOG_ARG_Str;
  __u32 val_off = off + sizeof(tag) + sizeof(__u16);
  long r;
  if (s.user)
    r = bpf_probe_read_user_str(rec + val_off, s.max, s.p);
  else
    r = bpf_probe_read_kernel_str(rec + val_off, s.max, s.p);
  // r counts the NUL, which is not sent.
  __u16 len = r > 0 ? r - 1 : 0;
  __builtin_memcpy(rec + off, &tag, sizeof(tag));
  __builtin_memcpy(rec + off + sizeof(tag), &len, sizeof(len));
  return __AYA_LOG_FIELD_SIZE(len);
}

// Sizers
// ------
// A sizer returns the maximum number of bytes its writer can write. The sum
// over all arguments is the ring buffer reservation. They mirror the writers
// above and are selected the same way, by __AYA_LOG_SIZER. Their results are
// constants after inlining, which the verifier requires for the reservation.

static __always_inline __u32 __aya_log_sz_int(__u64 v, __u32 sz) {
  return __AYA_LOG_FIELD_SIZE(sz);
}
static __always_inline __u32 __aya_log_sz_lit(const char *s, __u32 sz) {
  return __AYA_LOG_FIELD_SIZE(sz - 1);
}
static __always_inline __u32 __aya_log_sz_hex(struct aya_log_hex h, __u32 sz) {
  return __AYA_LOG_HINT_SIZE + __AYA_LOG_FIELD_SIZE(h.size);
}
static __always_inline __u32 __aya_log_sz_bytes(struct aya_log_bytes b,
                                                __u32 sz) {
  return __AYA_LOG_HINT_SIZE + __AYA_LOG_FIELD_SIZE(b.n);
}
static __always_inline __u32 __aya_log_sz_ip4(struct aya_log_ip4 a, __u32 sz) {
  return __AYA_LOG_FIELD_SIZE(sizeof(a.v));
}
static __always_inline __u32 __aya_log_sz_ip6(struct aya_log_ip6 a, __u32 sz) {
  return __AYA_LOG_FIELD_SIZE(16);
}
static __always_inline __u32 __aya_log_sz_mac(struct aya_log_mac m, __u32 sz) {
  return __AYA_LOG_HINT_SIZE + __AYA_LOG_FIELD_SIZE(6);
}
static __always_inline __u32 __aya_log_sz_ptr(struct aya_log_ptr p, __u32 sz) {
  return __AYA_LOG_HINT_SIZE + __AYA_LOG_FIELD_SIZE(sizeof(p.v));
}
static __always_inline __u32 __aya_log_sz_str(struct aya_log_str s, __u32 sz) {
  return __AYA_LOG_FIELD_SIZE(s.max);
}

// Dispatch on the argument type
// -----------------------------
// _Generic selects a function by the type of x; the caller then calls it with
// (rec, off, value, sz). Selecting a function instead of a call expression
// matters: every branch of _Generic must compile for every type, and only the
// selected function is ever called with x.

#define __AYA_LOG_WRITER(x)                                                    \
  _Generic((x),                                                                \
      char: __aya_log_w_i8,                                                    \
      signed char: __aya_log_w_i8,                                             \
      unsigned char: __aya_log_w_u8,                                           \
      short: __aya_log_w_i16,                                                  \
      unsigned short: __aya_log_w_u16,                                         \
      int: __aya_log_w_i32,                                                    \
      unsigned int: __aya_log_w_u32,                                           \
      long: __aya_log_w_i64,                                                   \
      unsigned long: __aya_log_w_u64,                                          \
      long long: __aya_log_w_i64,                                              \
      unsigned long long: __aya_log_w_u64,                                     \
      _Bool: __aya_log_w_u8,                                                   \
      char *: __aya_log_w_lit,                                                 \
      struct aya_log_hex: __aya_log_w_hex,                                     \
      struct aya_log_bytes: __aya_log_w_bytes,                                 \
      struct aya_log_ip4: __aya_log_w_ip4,                                     \
      struct aya_log_ip6: __aya_log_w_ip6,                                     \
      struct aya_log_mac: __aya_log_w_mac,                                     \
      struct aya_log_ptr: __aya_log_w_ptr,                                     \
      struct aya_log_str: __aya_log_w_str)

// Integers all share one sizer, which uses sz. Unsupported types are already
// rejected by __AYA_LOG_WRITER.
#define __AYA_LOG_SIZER(x)                                                     \
  _Generic((x),                                                                \
      char *: __aya_log_sz_lit,                                                \
      struct aya_log_hex: __aya_log_sz_hex,                                    \
      struct aya_log_bytes: __aya_log_sz_bytes,                                \
      struct aya_log_ip4: __aya_log_sz_ip4,                                    \
      struct aya_log_ip6: __aya_log_sz_ip6,                                    \
      struct aya_log_mac: __aya_log_sz_mac,                                    \
      struct aya_log_ptr: __aya_log_sz_ptr,                                    \
      struct aya_log_str: __aya_log_sz_str,                                    \
      default: __aya_log_sz_int)

// Number of wire arguments an argument produces, for the NumArgs field:
// helpers that send a DisplayHint before the value produce two.
#define __AYA_LOG_NARGS(x)                                                     \
  _Generic((x),                                                                \
      struct aya_log_hex: 2,                                                   \
      struct aya_log_bytes: 2,                                                 \
      struct aya_log_mac: 2,                                                   \
      struct aya_log_ptr: 2,                                                   \
      default: 1)

// Compile-time checks used by __AYA_LOG_DECL and __AYA_LOG_DECL_LAST.
#define __AYA_LOG_IS_RUNTIME_STR(x)                                            \
  _Generic((x), struct aya_log_str: 1, default: 0)
#define __AYA_LOG_IS_CHAR_PTR(x)                                               \
  _Generic((x), char *: 1, const char *: 1, default: 0)

// Iterating over the arguments
// ----------------------------
// The preprocessor has no loops, so __AYA_LOG_FE(m, l, args...) expands to
//   m(N, arg1) m(N-1, arg2) ... m(2, argN-1) l(1, argN)
// for N arguments. __AYA_LOG_FE_<k> handles k remaining arguments: it applies m
// to the first and passes the rest to __AYA_LOG_FE_<k-1>. __AYA_LOG_FE_1
// applies l to the last one, which is how the last argument gets different
// treatment (a runtime string is only allowed there). The first parameter of m
// and l is a number unique to the argument, used to name its temporary
// __aya_arg<i>.
//
// __AYA_LOG_PICK selects __AYA_LOG_FE_<N>: the arguments shift the list of
// __AYA_LOG_FE_* names so that the one matching the argument count lands in
// the N position. More than 16 arguments fails to compile.
//
// __AYA_LOG uses this four times: to declare the temporaries, to sum the
// sizes, to count the wire arguments and to write them.

#define __AYA_LOG_FE_1(m, l, x) l(1, x)
#define __AYA_LOG_FE_2(m, l, x, ...) m(2, x) __AYA_LOG_FE_1(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_3(m, l, x, ...) m(3, x) __AYA_LOG_FE_2(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_4(m, l, x, ...) m(4, x) __AYA_LOG_FE_3(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_5(m, l, x, ...) m(5, x) __AYA_LOG_FE_4(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_6(m, l, x, ...) m(6, x) __AYA_LOG_FE_5(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_7(m, l, x, ...) m(7, x) __AYA_LOG_FE_6(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_8(m, l, x, ...) m(8, x) __AYA_LOG_FE_7(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_9(m, l, x, ...) m(9, x) __AYA_LOG_FE_8(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_10(m, l, x, ...) m(10, x) __AYA_LOG_FE_9(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_11(m, l, x, ...)                                          \
  m(11, x) __AYA_LOG_FE_10(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_12(m, l, x, ...)                                          \
  m(12, x) __AYA_LOG_FE_11(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_13(m, l, x, ...)                                          \
  m(13, x) __AYA_LOG_FE_12(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_14(m, l, x, ...)                                          \
  m(14, x) __AYA_LOG_FE_13(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_15(m, l, x, ...)                                          \
  m(15, x) __AYA_LOG_FE_14(m, l, __VA_ARGS__)
#define __AYA_LOG_FE_16(m, l, x, ...)                                          \
  m(16, x) __AYA_LOG_FE_15(m, l, __VA_ARGS__)
#define __AYA_LOG_PICK(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, \
                       _14, _15, _16, N, ...)                                  \
  N
#define __AYA_LOG_FE(m, l, ...)                                                \
  __AYA_LOG_PICK(__VA_ARGS__, __AYA_LOG_FE_16, __AYA_LOG_FE_15,                \
                 __AYA_LOG_FE_14, __AYA_LOG_FE_13, __AYA_LOG_FE_12,            \
                 __AYA_LOG_FE_11, __AYA_LOG_FE_10, __AYA_LOG_FE_9,             \
                 __AYA_LOG_FE_8, __AYA_LOG_FE_7, __AYA_LOG_FE_6,               \
                 __AYA_LOG_FE_5, __AYA_LOG_FE_4, __AYA_LOG_FE_3,               \
                 __AYA_LOG_FE_2, __AYA_LOG_FE_1)                               \
  (m, l, __VA_ARGS__)

// Per-argument steps passed to __AYA_LOG_FE
// -----------------------------------------
// Each argument is evaluated exactly once, into the temporary __aya_arg<i>.
// The sizer and the writer both use the temporary, so an argument like
// bpf_get_prandom_u32() is not called twice. The original expression x only
// appears where it is not evaluated: sizeof, _Generic and
// __builtin_constant_p.

// Declares the temporary for the last argument. A char pointer or array is
// only accepted if it is a string literal, so that runtime strings have to go
// through LOG_FMT_STR, which bounds their size.
#define __AYA_LOG_DECL_LAST(i, x)                                              \
  _Static_assert(!__AYA_LOG_IS_CHAR_PTR(x) || __builtin_constant_p(x),         \
                 "runtime strings must be wrapped in LOG_FMT_STR or "          \
                 "LOG_FMT_USTR");                                              \
  __auto_type __aya_arg##i = (x);
// Same as __AYA_LOG_DECL_LAST, for all other arguments, which also must not be
// runtime strings.
#define __AYA_LOG_DECL(i, x)                                                   \
  _Static_assert(!__AYA_LOG_IS_RUNTIME_STR(x),                                 \
                 "LOG_FMT_STR and LOG_FMT_USTR must be the last argument");    \
  __AYA_LOG_DECL_LAST(i, x)
// "+ size": summed into the reservation size.
#define __AYA_LOG_SIZE(i, x) +__AYA_LOG_SIZER(x)(__aya_arg##i, sizeof(x))
// "+ count": summed into NumArgs.
#define __AYA_LOG_COUNT(i, x) +__AYA_LOG_NARGS(x)
// Writes the argument and advances the offset.
#define __AYA_LOG_WRITE(i, x)                                                  \
  __aya_off +=                                                                 \
      __AYA_LOG_WRITER(x)(__aya_rec, __aya_off, __aya_arg##i, sizeof(x));

// Builds and submits one record. Steps: check the level, evaluate the
// arguments, reserve header + argument sizes in the ring buffer, write the
// header and the arguments, then write the actual length at the start and
// submit. If the ring buffer is full the message is dropped.
#define __AYA_LOG(level, ...)                                                  \
  ({                                                                           \
    if ((level) <= AYA_LOG_LEVEL) {                                            \
      __AYA_LOG_FE(__AYA_LOG_DECL, __AYA_LOG_DECL_LAST, __VA_ARGS__)           \
      __u8 *__aya_rec = bpf_ringbuf_reserve(                                   \
          &AYA_LOGS,                                                           \
          __AYA_LOG_HEADER_SIZE __AYA_LOG_FE(__AYA_LOG_SIZE, __AYA_LOG_SIZE,   \
                                             __VA_ARGS__),                     \
          0);                                                                  \
      if (__aya_rec) {                                                         \
        __aya_rec = __builtin_assume_aligned(__aya_rec, 8);                    \
        __u32 __aya_off = __AYA_LOG_PREFIX_SIZE;                               \
        __u8 __aya_level = (level);                                            \
        __u32 __aya_line = __LINE__;                                           \
        __u32 __aya_nargs =                                                    \
            0 __AYA_LOG_FE(__AYA_LOG_COUNT, __AYA_LOG_COUNT, __VA_ARGS__);     \
        __aya_off +=                                                           \
            __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_Target, "", 0);   \
        __aya_off += __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_Level,   \
                                     &__aya_level, sizeof(__aya_level));       \
        __aya_off += __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_Module,  \
                                     __func__, __AYA_LOG_STRLEN(__func__));    \
        __aya_off +=                                                           \
            __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_File,             \
                            __FILE_NAME__, __AYA_LOG_STRLEN(__FILE_NAME__));   \
        __aya_off += __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_Line,    \
                                     &__aya_line, sizeof(__aya_line));         \
        __aya_off += __aya_log_field(__aya_rec, __aya_off, AYA_LOG_RF_NumArgs, \
                                     &__aya_nargs, sizeof(__aya_nargs));       \
        __AYA_LOG_FE(__AYA_LOG_WRITE, __AYA_LOG_WRITE, __VA_ARGS__)            \
        __u16 __aya_len = __aya_off;                                           \
        __builtin_memcpy(__aya_rec, &__aya_len, sizeof(__aya_len));            \
        bpf_ringbuf_submit(__aya_rec, 0);                                      \
      }                                                                        \
    }                                                                          \
  })

#define AYA_LOG_ERROR(...) __AYA_LOG(AYA_LOG_LEVEL_Error, __VA_ARGS__)
#define AYA_LOG_WARN(...) __AYA_LOG(AYA_LOG_LEVEL_Warn, __VA_ARGS__)
#define AYA_LOG_INFO(...) __AYA_LOG(AYA_LOG_LEVEL_Info, __VA_ARGS__)
#define AYA_LOG_DEBUG(...) __AYA_LOG(AYA_LOG_LEVEL_Debug, __VA_ARGS__)
#define AYA_LOG_TRACE(...) __AYA_LOG(AYA_LOG_LEVEL_Trace, __VA_ARGS__)
