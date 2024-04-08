/* SPDX-License-Identifier: GPL-2.0-only */
#pragma once

#include "vmlinux.h"
#include "common.bpf.h"

#define STRNCMP(s1, s1_sz, s2)                                    \
    ({                                                            \
        int result;                                               \
        if (bpf_core_enum_value_exists(enum bpf_func_id,          \
                                       BPF_FUNC_strncmp))         \
        {                                                         \
            result = bpf_strncmp(s1, s1_sz, s2);                  \
        }                                                         \
        else                                                      \
        {                                                         \
                                                                  \
            char *__cs = (s1);                                    \
            char *__ct = (s2);                                    \
            unsigned char __c1, __c2;                             \
            _Pragma("unroll") for (__u32 i = (s1_sz); i > 0; i--) \
            {                                                     \
                __c1 = *__cs++;                                   \
                __c2 = *__ct++;                                   \
                if (__c1 != __c2)                                 \
                {                                                 \
                    result = __c1 < __c2 ? -1 : 1;                \
                    break;                                        \
                }                                                 \
                if (!__c1)                                        \
                {                                                 \
                    result = 0;                                   \
                    break;                                        \
                }                                                 \
            }                                                     \
        }                                                         \
        result;                                                   \
    })
