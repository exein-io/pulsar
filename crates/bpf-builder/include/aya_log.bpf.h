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
// - Everything else is wrapped in a LOG_FMT_* helper (hex, IP and MAC
//   addresses, pointers, runtime strings and byte dumps).
// - A runtime string (LOG_FMT_STR, LOG_FMT_USTR) or byte dump
//   (LOG_FMT_HEX_BYTES) may only be the last argument. Passing a char pointer
//   or array directly is a compile error.
// - At most 16 arguments.
// - A message is only built when its level is enabled by AYA_LOG_LEVEL, which
//   userspace sets before load (aya_log::LEVEL). The default 0 disables
//   logging, and the verifier removes the disabled calls as dead code.
// - Every record carries the file name and line of the call. A function can
//   log with the location of its caller instead: the caller passes
//   AYA_LOG_HERE, and the function uses AYA_LOG_*_AT(site, ...):
//
//     static void check_at(const struct aya_log_site *site, int v) {
//       AYA_LOG_ERROR_AT(site, "bad value: ", v);
//     }
//     #define check(v) check_at(AYA_LOG_HERE, v)
//
// - AYA_LOG_FN defines an out-of-line function for one message, called with
//   AYA_LOG_CALL, see below. Use it for logs in loop bodies that are unrolled
//   on kernels without bpf_loop.
//
// Wire format (aya-log-common 0.2, all integers native-endian)
// -------------------------------------------------------------
//   record = [u16 record length, including these 2 bytes]
//            [header fields][arguments]
//   field  = [u8 tag][u16 value length][value]
//
// Header fields (tags from aya_log_record_field), each exactly once:
//   Target (string), Level (u8), Module (string), File (string), Line (u32),
//   NumArgs (u32). Target and Module are left empty; userspace sets the target
//   and prints file and line.
//
// Arguments (tags from aya_log_argument): NumArgs fields, concatenated in
// order by the decoder. A DisplayHint argument changes how the next value
// is printed (e.g. hex) and counts as an argument of its own.
//
// How a record is built
// ---------------------
// A call site does not write the record itself. It has a `static const`
// message template in .rodata, struct aya_log_msg followed by the record body:
// every tag, length and literal, a zeroed slot for each runtime value, and a
// patch list saying where the values go. The call site stores its values into
// an array on the stack and calls __aya_log_emit with the template, the site
// (file name and line, another .rodata constant) and the values. The emitter
// reserves the ring buffer slot, writes the fixed header fields, copies the
// body, patches the values, appends a trailing string or byte dump, and
// submits. A call site costs about fifteen instructions whatever the message.
//
// The templates are read-only map data at constant offsets, so the verifier
// reads their fields as constants when it walks the emitter for a call site:
// the reservation size and every offset are known to it.
//
// Adding an argument type
// -----------------------
// A struct for the helper to return, a __aya_log_mk_* function building it, a
// store function putting the value into the values array, a row in
// __AYA_LOG_TYPES, and, for a new way of patching, a kind in __aya_log_emit.

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

// Limits
// ------

// Bytes reserved for a runtime string (LOG_FMT_STR, LOG_FMT_USTR), including
// the NUL, and the cap of the n in LOG_FMT_STR_N.
#define AYA_LOG_STR_MAX 256
// Bytes reserved for a byte dump (LOG_FMT_HEX_BYTES), and the cap of its n.
#define AYA_LOG_BYTES_MAX 64
// Longest file name in a site.
#define AYA_LOG_FILE_MAX 32
// Most pieces in one message.
#define AYA_LOG_MAX_ARGS 16
// Longest record body: the tags, lengths, literals and value slots of one
// message. Exceeding it is a compile error.
#define AYA_LOG_BODY_MAX 192

// Not pinned: every eBPF object has its own AYA_LOGS map.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 16 * 1024);
} AYA_LOGS SEC(".maps");

// Highest enabled aya_log_level, set by userspace before load.
const volatile __u8 AYA_LOG_LEVEL = 0;

// Sites
// -----

// Where a message was logged.
struct aya_log_site {
  __u32 line;
  __u8 file_len;
  char file[AYA_LOG_FILE_MAX];
};

// A pointer to the site of the current line.
#define AYA_LOG_HERE                                                           \
  ({                                                                           \
    _Static_assert(sizeof(__FILE_NAME__) - 1 <= AYA_LOG_FILE_MAX,              \
                   "file name longer than AYA_LOG_FILE_MAX");                  \
    static const struct aya_log_site __aya_site = {                            \
        __LINE__, sizeof(__FILE_NAME__) - 1, __FILE_NAME__};                   \
    &__aya_site;                                                               \
  })

// Templates
// ---------

// How the emitter fills one runtime value into the record body.
enum __aya_log_patch_kind {
  __AYA_LOG_P_NONE = 0,  // a literal, nothing to patch
  __AYA_LOG_P_INT = 1,   // size bytes of the value itself
  __AYA_LOG_P_MEM = 2,   // 6 or 16 bytes from the values array
  __AYA_LOG_P_KSTR = 3,  // kernel string at the address in the value, appended
  __AYA_LOG_P_USTR = 4,  // user string at the address in the value, appended
  __AYA_LOG_P_BYTES = 5, // bytes at the kernel address in the value, appended
};

struct __aya_log_patch {
  __u16 off; // in the body
  __u8 kind; // enum __aya_log_patch_kind
  __u8 size;
};

// Head of a message template. The record body follows it directly. The fields
// are naturally aligned, because the emitter loads them from a map value and
// the verifier rejects misaligned loads on some architectures.
struct aya_log_msg {
  __u16 body_len;
  __u16 reserve; // ring buffer reservation: header + body + trailing piece
  __u8 level;
  __u8 npieces;
  __u16 pad;
  struct __aya_log_patch patch[AYA_LOG_MAX_ARGS];
};
_Static_assert(sizeof(struct aya_log_msg) % 8 == 0, "body must stay aligned");

// Body pieces, i.e. the TLV of each argument as it appears in the template.
// For a literal the characters follow the head as a separate member. For a
// runtime string or byte dump only the head is in the template; the emitter
// appends the data at the end of the record and fills in the length.
struct __aya_log_tlv_str {
  __u8 tag;
  __u16 len;
} __attribute__((packed));

struct __aya_log_tlv_bytes_h {
  __u8 htag;
  __u16 hlen;
  __u8 hint;
  __u8 tag;
  __u16 len;
} __attribute__((packed));

// Defines the TLV of a value type, plain and preceded by a DisplayHint.
#define __AYA_LOG_TLV(name, vtype)                                             \
  struct name {                                                                \
    __u8 tag;                                                                  \
    __u16 len;                                                                 \
    vtype v;                                                                   \
  } __attribute__((packed));                                                   \
  struct name##_h {                                                            \
    __u8 htag;                                                                 \
    __u16 hlen;                                                                \
    __u8 hint;                                                                 \
    __u8 tag;                                                                  \
    __u16 len;                                                                 \
    vtype v;                                                                   \
  } __attribute__((packed));

typedef __u8 __aya_log_u8x6[6];
typedef __u8 __aya_log_u8x16[16];
__AYA_LOG_TLV(__aya_log_tlv1, __u8)
__AYA_LOG_TLV(__aya_log_tlv2, __u16)
__AYA_LOG_TLV(__aya_log_tlv4, __u32)
__AYA_LOG_TLV(__aya_log_tlv8, __u64)
__AYA_LOG_TLV(__aya_log_tlv6, __aya_log_u8x6)
__AYA_LOG_TLV(__aya_log_tlv16, __aya_log_u8x16)

// The record up to the file name: length prefix, Target (empty), Level,
// Module (empty) and the head of File. The file name follows, then Line as a
// __aya_log_tlv4, then the body.
struct __aya_log_rec_head {
  __u16 rec_len;
  struct __aya_log_tlv_str target;
  struct __aya_log_tlv1 level;
  struct __aya_log_tlv_str module;
  struct __aya_log_tlv_str file;
} __attribute__((packed));

// Record bytes before the body, with the file name at its longest.
#define __AYA_LOG_FIXED_MAX                                                    \
  (sizeof(struct __aya_log_rec_head) + AYA_LOG_FILE_MAX +                      \
   sizeof(struct __aya_log_tlv4))

// Formatting helpers
// ------------------
// Each LOG_FMT_* helper returns a value of its own struct type, which is what
// the dispatch below keys on. The helpers are inline functions, not compound
// literals: the argument expressions appear inside the static template (in
// _Generic and sizeof) and clang 18 rejects a compound literal with a runtime
// value there.

#define __AYA_LOG_HEX_TYPES(X)                                                 \
  X(aya_log_hex1, __u8)                                                        \
  X(aya_log_hex2, __u16)                                                       \
  X(aya_log_hex4, __u32)                                                       \
  X(aya_log_hex8, __u64)                                                       \
  X(aya_log_uhex1, __u8)                                                       \
  X(aya_log_uhex2, __u16)                                                      \
  X(aya_log_uhex4, __u32)                                                      \
  X(aya_log_uhex8, __u64)

#define __AYA_LOG_DEF_STRUCT(name, vtype)                                      \
  struct name {                                                                \
    vtype v;                                                                   \
  };
__AYA_LOG_HEX_TYPES(__AYA_LOG_DEF_STRUCT)
__AYA_LOG_DEF_STRUCT(aya_log_ip4, __be32)
__AYA_LOG_DEF_STRUCT(aya_log_ip6, const void *)
__AYA_LOG_DEF_STRUCT(aya_log_mac, const void *)
__AYA_LOG_DEF_STRUCT(aya_log_umac, const void *)
__AYA_LOG_DEF_STRUCT(aya_log_ptr, __u64)

#define __AYA_LOG_DEF_MK(name, vtype)                                          \
  static __always_inline struct name __aya_log_mk_##name(vtype v) {            \
    return (struct name){v};                                                   \
  }
__AYA_LOG_HEX_TYPES(__AYA_LOG_DEF_MK)
__AYA_LOG_DEF_MK(aya_log_ip4, __be32)
__AYA_LOG_DEF_MK(aya_log_ip6, const void *)
__AYA_LOG_DEF_MK(aya_log_mac, const void *)
__AYA_LOG_DEF_MK(aya_log_umac, const void *)
__AYA_LOG_DEF_MK(aya_log_ptr, __u64)

// Trailing pieces: data at p, n bytes or characters at most.
#define __AYA_LOG_DEF_TRAILING(name)                                           \
  struct name {                                                                \
    const void *p;                                                             \
    __u32 n;                                                                   \
  };                                                                           \
  static __always_inline struct name __aya_log_mk_##name(const void *p,        \
                                                         __u32 n) {            \
    return (struct name){p, n};                                                \
  }
__AYA_LOG_DEF_TRAILING(aya_log_kstr)
__AYA_LOG_DEF_TRAILING(aya_log_ustr)
__AYA_LOG_DEF_TRAILING(aya_log_hexbytes)
__AYA_LOG_DEF_TRAILING(aya_log_uhexbytes)

// Picks the hex struct of the width of x. The casts keep clang from warning
// about a constant that does not fit the narrower branches.
#define __AYA_LOG_BY_WIDTH(x, pfx)                                             \
  __builtin_choose_expr(                                                       \
      sizeof(x) == 1, __aya_log_mk_##pfx##1((__u8)(x)),                        \
      __builtin_choose_expr(                                                   \
          sizeof(x) == 2, __aya_log_mk_##pfx##2((__u16)(x)),                   \
          __builtin_choose_expr(sizeof(x) == 4,                                \
                                __aya_log_mk_##pfx##4((__u32)(x)),             \
                                __aya_log_mk_##pfx##8((__u64)(x)))))

// Integer in lower or upper case hex, e.g. "ff". Printed with the width of x.
#define LOG_FMT_HEX(x) __AYA_LOG_BY_WIDTH(x, aya_log_hex)
#define LOG_FMT_UHEX(x) __AYA_LOG_BY_WIDTH(x, aya_log_uhex)
// IPv4 address in network byte order, e.g. "10.0.0.1".
#define LOG_FMT_IP4(be32) __aya_log_mk_aya_log_ip4(be32)
// 16 bytes at kernel address p as an IPv6 address, e.g. "2001:db8::1".
#define LOG_FMT_IP6(p) __aya_log_mk_aya_log_ip6(p)
// 6 bytes at kernel address p as a MAC address, e.g. "aa:bb:cc:01:02:03".
#define LOG_FMT_MAC(p) __aya_log_mk_aya_log_mac(p)
#define LOG_FMT_UMAC(p) __aya_log_mk_aya_log_umac(p)
// Pointer value, e.g. "0xffff8b7394f03240".
#define LOG_FMT_PTR(p) __aya_log_mk_aya_log_ptr((__u64)(p))
// NUL-terminated string at p in kernel (STR) or user (USTR) memory, read with
// bpf_probe_read_{kernel,user}_str. At most n - 1 characters are printed, and
// n is capped at AYA_LOG_STR_MAX. Only allowed as the last argument.
#define LOG_FMT_STR_N(p, n) __aya_log_mk_aya_log_kstr((p), (n))
#define LOG_FMT_USTR_N(p, n) __aya_log_mk_aya_log_ustr((p), (n))
#define LOG_FMT_STR(p) LOG_FMT_STR_N(p, AYA_LOG_STR_MAX)
#define LOG_FMT_USTR(p) LOG_FMT_USTR_N(p, AYA_LOG_STR_MAX)
// n bytes at kernel address p in lower or upper case hex, e.g. "deadbeef". n
// is capped at AYA_LOG_BYTES_MAX. Only allowed as the last argument.
#define LOG_FMT_HEX_BYTES(p, n) __aya_log_mk_aya_log_hexbytes((p), (n))
#define LOG_FMT_UHEX_BYTES(p, n) __aya_log_mk_aya_log_uhexbytes((p), (n))

// Value stores
// ------------
// One function per argument type appends what the emitter needs to the values
// array, through the running pointer vp: the value itself, the bytes of an
// address, or for a trailing piece the address to read from and the length
// limit. Literals append nothing. The emitter consumes the values in the same
// order.

static __always_inline void __aya_log_v_lit(__u64 **vp, const char *s) {}
static __always_inline void __aya_log_v_int(__u64 **vp, __u64 v) {
  *(*vp)++ = v;
}
#define __AYA_LOG_DEF_V(name, vtype)                                           \
  static __always_inline void __aya_log_v_##name(__u64 **vp, struct name h) {  \
    *(*vp)++ = (__u64)h.v;                                                     \
  }
__AYA_LOG_HEX_TYPES(__AYA_LOG_DEF_V)
__AYA_LOG_DEF_V(aya_log_ip4, __be32)
// IPv6 and MAC addresses are copied into the values array here, so the
// emitter only has to move bytes.
#define __AYA_LOG_SLOTS_OF(type)                                               \
  ((sizeof(type) + sizeof(__u64) - 1) / sizeof(__u64))
#define __AYA_LOG_DEF_V_MEM(name, type)                                        \
  static __always_inline void __aya_log_v_##name(__u64 **vp, struct name m) {  \
    __u32 slots = __AYA_LOG_SLOTS_OF(type);                                    \
    (*vp)[slots - 1] = 0;                                                      \
    bpf_probe_read_kernel(*vp, sizeof(type), m.v);                             \
    *vp += slots;                                                              \
  }
__AYA_LOG_DEF_V_MEM(aya_log_ip6, __aya_log_u8x16)
__AYA_LOG_DEF_V_MEM(aya_log_mac, __aya_log_u8x6)
__AYA_LOG_DEF_V_MEM(aya_log_umac, __aya_log_u8x6)
__AYA_LOG_DEF_V(aya_log_ptr, __u64)
#define __AYA_LOG_DEF_V_TRAILING(name)                                         \
  static __always_inline void __aya_log_v_##name(__u64 **vp, struct name t) {  \
    *(*vp)++ = (__u64)t.p;                                                     \
    *(*vp)++ = t.n;                                                            \
  }
__AYA_LOG_DEF_V_TRAILING(aya_log_kstr)
__AYA_LOG_DEF_V_TRAILING(aya_log_ustr)
__AYA_LOG_DEF_V_TRAILING(aya_log_hexbytes)
__AYA_LOG_DEF_V_TRAILING(aya_log_uhexbytes)

// Dispatch on the argument type
// -----------------------------
// One row per supported type, X(ctype, head, kind, size, voff, nwire, store):
//   head   the template piece: a compound literal of its TLV struct with the
//          tags and lengths filled in and the value zeroed; its type is also
//          the member type in the template
//   kind   __aya_log_patch_kind
//   size   bytes the emitter stores or reads
//   voff   offset of the patched field in the piece
//   nwire  wire arguments the piece produces (a hint counts as one)
//   store  the value store function above
// String literals are not in the table: they need sizeof(x), and are handled
// first in every _Generic below.

// Size of the value of a TLV struct.
#define __AYA_LOG_VSIZE(tlv) sizeof(((struct tlv *)0)->v)

// A row for a plain TLV, and for one preceded by a DisplayHint, which counts
// as a wire argument of its own.
#define __AYA_LOG_ROW(X, ctype, tlv, tag, kind, store)                         \
  X(ctype, ((struct tlv){tag, __AYA_LOG_VSIZE(tlv)}), kind,                    \
    __AYA_LOG_VSIZE(tlv), __builtin_offsetof(struct tlv, v), 1, store)
#define __AYA_LOG_ROW_H(X, ctype, tlv, tag, hint, kind, store)                 \
  X(ctype,                                                                     \
    ((struct tlv##_h){AYA_LOG_ARG_DisplayHint, sizeof(__u8), hint, tag,        \
                      __AYA_LOG_VSIZE(tlv)}),                                  \
    kind, __AYA_LOG_VSIZE(tlv), __builtin_offsetof(struct tlv##_h, v), 2,      \
    store)
// A row for a trailing piece: only its head is in the template, and the
// emitter fills in the length.
#define __AYA_LOG_ROW_STR(X, ctype, kind, store)                               \
  X(ctype, ((struct __aya_log_tlv_str){AYA_LOG_ARG_Str, 0}), kind, 0,          \
    __builtin_offsetof(struct __aya_log_tlv_str, tag), 1, store)
#define __AYA_LOG_ROW_BYTES(X, ctype, hint, store)                             \
  X(ctype,                                                                     \
    ((struct __aya_log_tlv_bytes_h){AYA_LOG_ARG_DisplayHint, sizeof(__u8),     \
                                    hint, AYA_LOG_ARG_Bytes, 0}),              \
    __AYA_LOG_P_BYTES, 0,                                                      \
    __builtin_offsetof(struct __aya_log_tlv_bytes_h, tag), 2, store)

#define __AYA_LOG_TYPES(X)                                                     \
  __AYA_LOG_ROW(X, char, __aya_log_tlv1, AYA_LOG_ARG_I8, __AYA_LOG_P_INT,      \
                __aya_log_v_int)                                               \
  __AYA_LOG_ROW(X, signed char, __aya_log_tlv1, AYA_LOG_ARG_I8,                \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, unsigned char, __aya_log_tlv1, AYA_LOG_ARG_U8,              \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, _Bool, __aya_log_tlv1, AYA_LOG_ARG_U8, __AYA_LOG_P_INT,     \
                __aya_log_v_int)                                               \
  __AYA_LOG_ROW(X, short, __aya_log_tlv2, AYA_LOG_ARG_I16, __AYA_LOG_P_INT,    \
                __aya_log_v_int)                                               \
  __AYA_LOG_ROW(X, unsigned short, __aya_log_tlv2, AYA_LOG_ARG_U16,            \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, int, __aya_log_tlv4, AYA_LOG_ARG_I32, __AYA_LOG_P_INT,      \
                __aya_log_v_int)                                               \
  __AYA_LOG_ROW(X, unsigned int, __aya_log_tlv4, AYA_LOG_ARG_U32,              \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, long, __aya_log_tlv8, AYA_LOG_ARG_I64, __AYA_LOG_P_INT,     \
                __aya_log_v_int)                                               \
  __AYA_LOG_ROW(X, unsigned long, __aya_log_tlv8, AYA_LOG_ARG_U64,             \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, long long, __aya_log_tlv8, AYA_LOG_ARG_I64,                 \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW(X, unsigned long long, __aya_log_tlv8, AYA_LOG_ARG_U64,        \
                __AYA_LOG_P_INT, __aya_log_v_int)                              \
  __AYA_LOG_ROW_H(X, struct aya_log_hex1, __aya_log_tlv1, AYA_LOG_ARG_U8,      \
                  AYA_LOG_HINT_LowerHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_hex1)                                    \
  __AYA_LOG_ROW_H(X, struct aya_log_hex2, __aya_log_tlv2, AYA_LOG_ARG_U16,     \
                  AYA_LOG_HINT_LowerHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_hex2)                                    \
  __AYA_LOG_ROW_H(X, struct aya_log_hex4, __aya_log_tlv4, AYA_LOG_ARG_U32,     \
                  AYA_LOG_HINT_LowerHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_hex4)                                    \
  __AYA_LOG_ROW_H(X, struct aya_log_hex8, __aya_log_tlv8, AYA_LOG_ARG_U64,     \
                  AYA_LOG_HINT_LowerHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_hex8)                                    \
  __AYA_LOG_ROW_H(X, struct aya_log_uhex1, __aya_log_tlv1, AYA_LOG_ARG_U8,     \
                  AYA_LOG_HINT_UpperHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_uhex1)                                   \
  __AYA_LOG_ROW_H(X, struct aya_log_uhex2, __aya_log_tlv2, AYA_LOG_ARG_U16,    \
                  AYA_LOG_HINT_UpperHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_uhex2)                                   \
  __AYA_LOG_ROW_H(X, struct aya_log_uhex4, __aya_log_tlv4, AYA_LOG_ARG_U32,    \
                  AYA_LOG_HINT_UpperHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_uhex4)                                   \
  __AYA_LOG_ROW_H(X, struct aya_log_uhex8, __aya_log_tlv8, AYA_LOG_ARG_U64,    \
                  AYA_LOG_HINT_UpperHex, __AYA_LOG_P_INT,                      \
                  __aya_log_v_aya_log_uhex8)                                   \
  __AYA_LOG_ROW_H(X, struct aya_log_ptr, __aya_log_tlv8, AYA_LOG_ARG_Pointer,  \
                  AYA_LOG_HINT_Pointer, __AYA_LOG_P_INT,                       \
                  __aya_log_v_aya_log_ptr)                                     \
  __AYA_LOG_ROW(X, struct aya_log_ip4, __aya_log_tlv4, AYA_LOG_ARG_Ipv4Addr,   \
                __AYA_LOG_P_INT, __aya_log_v_aya_log_ip4)                      \
  __AYA_LOG_ROW(X, struct aya_log_ip6, __aya_log_tlv16, AYA_LOG_ARG_Ipv6Addr,  \
                __AYA_LOG_P_MEM, __aya_log_v_aya_log_ip6)                      \
  __AYA_LOG_ROW_H(X, struct aya_log_mac, __aya_log_tlv6,                       \
                  AYA_LOG_ARG_ArrU8Len6, AYA_LOG_HINT_LowerMac,                \
                  __AYA_LOG_P_MEM, __aya_log_v_aya_log_mac)                    \
  __AYA_LOG_ROW_H(X, struct aya_log_umac, __aya_log_tlv6,                      \
                  AYA_LOG_ARG_ArrU8Len6, AYA_LOG_HINT_UpperMac,                \
                  __AYA_LOG_P_MEM, __aya_log_v_aya_log_umac)                   \
  __AYA_LOG_ROW_STR(X, struct aya_log_kstr, __AYA_LOG_P_KSTR,                  \
                    __aya_log_v_aya_log_kstr)                                  \
  __AYA_LOG_ROW_STR(X, struct aya_log_ustr, __AYA_LOG_P_USTR,                  \
                    __aya_log_v_aya_log_ustr)                                  \
  __AYA_LOG_ROW_BYTES(X, struct aya_log_hexbytes, AYA_LOG_HINT_LowerHex,       \
                      __aya_log_v_aya_log_hexbytes)                            \
  __AYA_LOG_ROW_BYTES(X, struct aya_log_uhexbytes, AYA_LOG_HINT_UpperHex,      \
                      __aya_log_v_aya_log_uhexbytes)

// Each _Generic lists the literal first, then one association per row. The
// row macros expand with a leading comma, which avoids a trailing one.
#define __AYA_LOG_X_HEAD(ctype, head, kind, size, voff, nwire, store)          \
  , ctype : head
#define __AYA_LOG_X_KIND(ctype, head, kind, size, voff, nwire, store)          \
  , ctype : kind
#define __AYA_LOG_X_SIZE(ctype, head, kind, size, voff, nwire, store)          \
  , ctype : size
#define __AYA_LOG_X_VOFF(ctype, head, kind, size, voff, nwire, store)          \
  , ctype : voff
#define __AYA_LOG_X_NWIRE(ctype, head, kind, size, voff, nwire, store)         \
  , ctype : nwire
#define __AYA_LOG_X_STORE(ctype, head, kind, size, voff, nwire, store)         \
  , ctype : store

// The characters of a literal and their count. Empty for everything else, so
// the member for the characters has no size for other pieces.
#define __AYA_LOG_LIT(x) _Generic((x), char *: (x), default: "")
#define __AYA_LOG_LITLEN(x) (sizeof(__AYA_LOG_LIT(x)) - 1)
// The template piece of a literal: the head, the characters follow it.
#define __AYA_LOG_LIT_HEAD(x)                                                  \
  ((struct __aya_log_tlv_str){AYA_LOG_ARG_Str, __AYA_LOG_LITLEN(x)})

#define __AYA_LOG_HEAD(x)                                                      \
  _Generic((x), char *: __AYA_LOG_LIT_HEAD(x) __AYA_LOG_TYPES(__AYA_LOG_X_HEAD))
#define __AYA_LOG_KIND(x)                                                      \
  _Generic((x), char *: __AYA_LOG_P_NONE __AYA_LOG_TYPES(__AYA_LOG_X_KIND))
#define __AYA_LOG_SIZE(x)                                                      \
  _Generic((x), char *: 0 __AYA_LOG_TYPES(__AYA_LOG_X_SIZE))
#define __AYA_LOG_VOFF(x)                                                      \
  _Generic((x), char *: 0 __AYA_LOG_TYPES(__AYA_LOG_X_VOFF))
#define __AYA_LOG_NWIRE(x)                                                     \
  _Generic((x), char *: 1 __AYA_LOG_TYPES(__AYA_LOG_X_NWIRE))
#define __AYA_LOG_STORE(x)                                                     \
  _Generic((x), char *: __aya_log_v_lit __AYA_LOG_TYPES(__AYA_LOG_X_STORE))

// Bytes to reserve after the body for a trailing piece.
#define __AYA_LOG_TRAILING_MAX(x)                                              \
  _Generic((x),                                                                \
      struct aya_log_kstr: AYA_LOG_STR_MAX,                                    \
      struct aya_log_ustr: AYA_LOG_STR_MAX,                                    \
      struct aya_log_hexbytes: AYA_LOG_BYTES_MAX,                              \
      struct aya_log_uhexbytes: AYA_LOG_BYTES_MAX,                             \
      default: 0)
#define __AYA_LOG_IS_TRAILING(x) (__AYA_LOG_TRAILING_MAX(x) != 0)
// Slots a piece takes in the values array, and the most in one message.
#define __AYA_LOG_MAX_VALS (2 * AYA_LOG_MAX_ARGS)
#define __AYA_LOG_NVALS(x)                                                     \
  _Generic((x),                                                                \
      char *: 0,                                                               \
      struct aya_log_ip6: __AYA_LOG_SLOTS_OF(__aya_log_u8x16),                 \
      default: __AYA_LOG_IS_TRAILING(x) ? 2 : 1)
#define __AYA_LOG_IS_CHAR_PTR(x)                                               \
  _Generic((x), char *: 1, const char *: 1, default: 0)

// Iterating over the arguments
// ----------------------------
// The preprocessor has no loops, so __AYA_LOG_FE(m, l, args...) expands to
//   m(N, arg1) m(N-1, arg2) ... m(2, argN-1) l(1, argN)
// for N arguments. __AYA_LOG_FE_<k> handles k remaining arguments: it applies m
// to the first and passes the rest to __AYA_LOG_FE_<k-1>. __AYA_LOG_FE_1
// applies l to the last one, which is how the last argument gets different
// treatment (a trailing piece is only allowed there). The first parameter of m
// and l is a number unique to the argument, used to name its temporary and
// template members.
//
// __AYA_LOG_PICK selects __AYA_LOG_FE_<N>: the arguments shift the list of
// __AYA_LOG_FE_* names so that the one matching the argument count lands in
// the N position. More than 16 arguments fails to compile. __AYA_LOG_NARGS
// uses the same trick to get N itself.

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
#define __AYA_LOG_NARGS(...)                                                   \
  __AYA_LOG_PICK(__VA_ARGS__, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, \
                 2, 1)

// Per-argument steps passed to __AYA_LOG_FE
// -----------------------------------------
// Each argument is evaluated exactly once, into the temporary __aya_arg<i>.
// The original expression x only appears where it is not evaluated: sizeof,
// _Generic and __builtin_constant_p.

// Declares the temporary for the last argument. A char pointer or array is
// only accepted if it is a string literal, so that runtime strings have to go
// through LOG_FMT_STR, which bounds their size.
#define __AYA_LOG_DECL_LAST(i, x)                                              \
  _Static_assert(!__AYA_LOG_IS_CHAR_PTR(x) || __builtin_constant_p(x),         \
                 "runtime strings must be wrapped in LOG_FMT_STR or "          \
                 "LOG_FMT_USTR");                                              \
  __auto_type __aya_arg##i = (x);
// Same as __AYA_LOG_DECL_LAST, for all other arguments, which also must not be
// trailing pieces.
#define __AYA_LOG_DECL(i, x)                                                   \
  _Static_assert(!__AYA_LOG_IS_TRAILING(x),                                    \
                 "LOG_FMT_STR, LOG_FMT_USTR and LOG_FMT_HEX_BYTES must be "    \
                 "the last argument");                                         \
  __AYA_LOG_DECL_LAST(i, x)
// Template members of one piece: its TLV head and, for a literal, the
// characters.
#define __AYA_LOG_MEMBER(i, x)                                                 \
  __typeof__(__AYA_LOG_HEAD(x)) __aya_m##i;                                    \
  char __aya_s##i[__AYA_LOG_LITLEN(x)];
// Their initializers.
#define __AYA_LOG_INIT(i, x)                                                   \
  .__aya_m##i = __AYA_LOG_HEAD(x), .__aya_s##i = __AYA_LOG_LIT(x),
// The patch entry, with the offset of the patched field in the body.
#define __AYA_LOG_PATCH(i, x)                                                  \
  {__builtin_offsetof(__typeof__(__aya_msg), __aya_m##i) -                     \
       sizeof(struct aya_log_msg) + __AYA_LOG_VOFF(x),                         \
   __AYA_LOG_KIND(x), __AYA_LOG_SIZE(x)},
// "+ count": summed into NumArgs.
#define __AYA_LOG_COUNT(i, x) +__AYA_LOG_NWIRE(x)
// "+ slots": summed into the size of the values array.
#define __AYA_LOG_SLOTS(i, x) +__AYA_LOG_NVALS(x)
// Appends the value to the values array.
#define __AYA_LOG_STORE_VAL(i, x) __AYA_LOG_STORE(x)(&__aya_vp, __aya_arg##i);
// Expand to the last argument and to nothing, for __AYA_LOG_FE.
#define __AYA_LOG_NONE(i, x)
#define __AYA_LOG_SELF(i, x) x

// Builds and submits one record for the given site. Steps: check the level,
// evaluate the arguments, define the template, store the values and call the
// emitter.
#define __AYA_LOG_AT(site, lvl, ...)                                           \
  ({                                                                           \
    if ((lvl) <= AYA_LOG_LEVEL) {                                              \
      __AYA_LOG_FE(__AYA_LOG_DECL, __AYA_LOG_DECL_LAST, __VA_ARGS__)           \
      static const struct __attribute__((packed)) {                            \
        struct aya_log_msg hdr;                                                \
        struct __aya_log_tlv4 nargs;                                           \
        __AYA_LOG_FE(__AYA_LOG_MEMBER, __AYA_LOG_MEMBER, __VA_ARGS__)          \
      } __aya_msg __attribute__((aligned(8))) = {                              \
          .hdr =                                                               \
              {                                                                \
                  .body_len = sizeof(__aya_msg) - sizeof(struct aya_log_msg),  \
                  .reserve =                                                   \
                      __AYA_LOG_FIXED_MAX + sizeof(__aya_msg) -                \
                      sizeof(struct aya_log_msg) +                             \
                      __AYA_LOG_TRAILING_MAX(__AYA_LOG_FE(                     \
                          __AYA_LOG_NONE, __AYA_LOG_SELF, __VA_ARGS__)),       \
                  .level = (lvl),                                              \
                  .npieces = __AYA_LOG_NARGS(__VA_ARGS__),                     \
                  .patch = {__AYA_LOG_FE(__AYA_LOG_PATCH, __AYA_LOG_PATCH,     \
                                         __VA_ARGS__)},                        \
              },                                                               \
          .nargs = {AYA_LOG_RF_NumArgs, 4,                                     \
                    0 __AYA_LOG_FE(__AYA_LOG_COUNT, __AYA_LOG_COUNT,           \
                                   __VA_ARGS__)},                              \
          __AYA_LOG_FE(__AYA_LOG_INIT, __AYA_LOG_INIT, __VA_ARGS__)};          \
      _Static_assert(sizeof(__aya_msg) - sizeof(struct aya_log_msg) <=         \
                         AYA_LOG_BODY_MAX,                                     \
                     "message longer than AYA_LOG_BODY_MAX");                  \
      _Static_assert(__builtin_offsetof(__typeof__(__aya_msg), __aya_s1) +     \
                             sizeof(__aya_msg.__aya_s1) ==                     \
                         sizeof(__aya_msg),                                    \
                     "template has tail padding");                             \
      __u64 __aya_vals[0 __AYA_LOG_FE(__AYA_LOG_SLOTS, __AYA_LOG_SLOTS,        \
                                      __VA_ARGS__)];                           \
      __u64 *__aya_vp = __aya_vals;                                            \
      __AYA_LOG_FE(__AYA_LOG_STORE_VAL, __AYA_LOG_STORE_VAL, __VA_ARGS__)      \
      __aya_log_emit((site), &__aya_msg.hdr, __aya_vals);                      \
    }                                                                          \
  })

#define __AYA_LOG(lvl, ...) __AYA_LOG_AT(AYA_LOG_HERE, lvl, __VA_ARGS__)

#define AYA_LOG_ERROR(...) __AYA_LOG(AYA_LOG_LEVEL_Error, __VA_ARGS__)
#define AYA_LOG_WARN(...) __AYA_LOG(AYA_LOG_LEVEL_Warn, __VA_ARGS__)
#define AYA_LOG_INFO(...) __AYA_LOG(AYA_LOG_LEVEL_Info, __VA_ARGS__)
#define AYA_LOG_DEBUG(...) __AYA_LOG(AYA_LOG_LEVEL_Debug, __VA_ARGS__)
#define AYA_LOG_TRACE(...) __AYA_LOG(AYA_LOG_LEVEL_Trace, __VA_ARGS__)

#define AYA_LOG_ERROR_AT(site, ...)                                            \
  __AYA_LOG_AT(site, AYA_LOG_LEVEL_Error, __VA_ARGS__)
#define AYA_LOG_WARN_AT(site, ...)                                             \
  __AYA_LOG_AT(site, AYA_LOG_LEVEL_Warn, __VA_ARGS__)
#define AYA_LOG_INFO_AT(site, ...)                                             \
  __AYA_LOG_AT(site, AYA_LOG_LEVEL_Info, __VA_ARGS__)
#define AYA_LOG_DEBUG_AT(site, ...)                                            \
  __AYA_LOG_AT(site, AYA_LOG_LEVEL_Debug, __VA_ARGS__)
#define AYA_LOG_TRACE_AT(site, ...)                                            \
  __AYA_LOG_AT(site, AYA_LOG_LEVEL_Trace, __VA_ARGS__)

// Out-of-line log functions
// -------------------------
// AYA_LOG_FN(name, level, (params), pieces...) defines
//
//   static __noinline void name(const struct aya_log_site *site, params)
//
// which logs the pieces at the given level with the caller's location. Call
// it with AYA_LOG_CALL(name, args...), which passes AYA_LOG_HERE. A call costs
// about one instruction per argument, an inline AYA_LOG_* about fifteen, and
// a loop unrolled on kernels without bpf_loop multiplies that.
//
//   AYA_LOG_FN(log_bad_offset, AYA_LOG_LEVEL_Error, (u32 off, u32 len),
//              "offset out of bounds: ", off, "+", len)
//   ...
//   AYA_LOG_CALL(log_bad_offset, offset, len);
#define __AYA_LOG_PARAMS(...) , ##__VA_ARGS__
#define AYA_LOG_FN(name, lvl, params, ...)                                     \
  static __noinline void name(                                                 \
      const struct aya_log_site *site __AYA_LOG_PARAMS params) {               \
    __AYA_LOG_AT(site, lvl, __VA_ARGS__);                                      \
  }
#define AYA_LOG_CALL(name, ...) name(AYA_LOG_HERE, ##__VA_ARGS__)

// The emitter
// -----------
// Shared by all call sites of an object. Writes the record described by msg
// and site, with the runtime values in vals, into the ring buffer. If the ring
// buffer is full the message is dropped.
//
// The bounds checks are for the verifier. When it knows the template values,
// which is the case whenever the reservation below is accepted, they fold
// away.

static __always_inline void __aya_log_put16(__u8 *dst, __u16 v) {
  dst[0] = v;
  dst[1] = v >> 8;
}

static __always_inline void __aya_log_put32(__u8 *dst, __u32 v) {
  __aya_log_put16(dst, v);
  __aya_log_put16(dst + sizeof(__u16), v >> 16);
}

static __always_inline void __aya_log_put64(__u8 *dst, __u64 v) {
  __aya_log_put32(dst, v);
  __aya_log_put32(dst + sizeof(__u32), v >> 32);
}

static __noinline void __aya_log_emit(const struct aya_log_site *site,
                                      const struct aya_log_msg *msg,
                                      const __u64 *vals) {
  __u8 *rec = bpf_ringbuf_reserve(&AYA_LOGS, msg->reserve, 0);
  if (!rec)
    return;

  // Line is written before the file name, so that nothing of the site is
  // needed after the file name copy.
  struct __aya_log_rec_head *head = (struct __aya_log_rec_head *)rec;
  __u32 file_len = site->file_len;
  if (file_len > AYA_LOG_FILE_MAX)
    file_len = AYA_LOG_FILE_MAX;
  head->target.tag = AYA_LOG_RF_Target;
  head->target.len = 0;
  head->level.tag = AYA_LOG_RF_Level;
  head->level.len = sizeof(head->level.v);
  head->level.v = msg->level;
  head->module.tag = AYA_LOG_RF_Module;
  head->module.len = 0;
  head->file.tag = AYA_LOG_RF_File;
  head->file.len = file_len;
  __u8 *file = rec + sizeof(*head);
  struct __aya_log_tlv4 *line = (struct __aya_log_tlv4 *)(file + file_len);
  line->tag = AYA_LOG_RF_Line;
  line->len = sizeof(line->v);
  line->v = site->line;
  bpf_probe_read_kernel(file, file_len, site->file);
  __u32 off = sizeof(*head) + file_len + sizeof(*line);

  // The body: NumArgs and the pieces, with the values zeroed.
  __u32 body_len = msg->body_len;
  if (body_len > AYA_LOG_BODY_MAX)
    body_len = AYA_LOG_BODY_MAX;
  bpf_probe_read_kernel(rec + off, body_len, msg + 1);
  __u32 len = off + body_len;

  // Patch the values in. A trailing piece ends the loop and is handled after
  // it, so the loop makes no helper calls.
  __u32 npieces = msg->npieces;
  __u32 slot = 0;
  __u8 kind = __AYA_LOG_P_NONE;
  __u8 *dst = rec;
  for (__u32 i = 0; i < AYA_LOG_MAX_ARGS; i++) {
    if (i >= npieces)
      break;
    const struct __aya_log_patch *p = &msg->patch[i];
    kind = p->kind;
    if (kind == __AYA_LOG_P_NONE)
      continue;
    if (slot >= __AYA_LOG_MAX_VALS)
      break;
    __u32 poff = off + p->off;
    if (poff > __AYA_LOG_FIXED_MAX + AYA_LOG_BODY_MAX)
      poff = 0;
    dst = rec + poff;
    if (kind >= __AYA_LOG_P_KSTR)
      break;
    __u64 v = vals[slot++];
    if (kind == __AYA_LOG_P_INT) {
      switch (p->size) {
      case sizeof(__u8):
        dst[0] = v;
        break;
      case sizeof(__u16):
        __aya_log_put16(dst, v);
        break;
      case sizeof(__u32):
        __aya_log_put32(dst, v);
        break;
      default:
        __aya_log_put64(dst, v);
        break;
      }
    } else if (p->size == sizeof(__aya_log_u8x6)) {
      __aya_log_put32(dst, v);
      __aya_log_put16(dst + sizeof(__u32), v >> 32);
    } else {
      __aya_log_put64(dst, v);
      __aya_log_put64(dst + sizeof(__u64), vals[slot++]);
    }
  }

  if (kind >= __AYA_LOG_P_KSTR && slot + 1 < __AYA_LOG_MAX_VALS) {
    // dst is the head of the piece, the data goes after the body.
    const void *src = (const void *)vals[slot];
    __u32 n = vals[slot + 1];
    if (kind == __AYA_LOG_P_BYTES) {
      if (n > AYA_LOG_BYTES_MAX)
        n = AYA_LOG_BYTES_MAX;
      bpf_probe_read_kernel(rec + len, n, src);
    } else {
      // r counts the NUL, which is not sent.
      if (n > AYA_LOG_STR_MAX)
        n = AYA_LOG_STR_MAX;
      long r;
      if (kind == __AYA_LOG_P_USTR)
        r = bpf_probe_read_user_str(rec + len, n, src);
      else
        r = bpf_probe_read_kernel_str(rec + len, n, src);
      n = r > 0 ? r - 1 : 0;
    }
    ((struct __aya_log_tlv_str *)dst)->len = n;
    len += n;
  }

  head->rec_len = len;
  bpf_ringbuf_submit(rec, 0);
}
