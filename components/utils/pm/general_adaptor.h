// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __general_adaptor_h__
#define __general_adaptor_h__

#include "stdint.h"
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include "common.h"
#include "debug.h"
#include "debugpm.h"

typedef unsigned int u_int;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef bool boolean_cpt;
typedef bool BOOL;
typedef uint64_t u_int64;

#define TRUE true
#define FALSE false

#define CP_INLINE inline
#define CP_CACHELINE_SIZE 64
#define CP_CACHELINE_ALIGNED __attribute__((__aligned__(CP_CACHELINE_SIZE)))
#define CP_MAYBE_UNUSED CP_UNUSED

#define KISS_OFFSETOF(str_name, field_name) offsetof(str_name, field_name)

#define KISS_ASSERT_COMPILE_TIME(cond) extern int __kiss_assert_dummy[(cond)?1:-1]

#define KISS_ASSERT_PERF(...)
#define ASSERT_LOCKED
#define kiss_multik_this_instance_num (0)

typedef enum {
    KISS_ERROR = -1,
    KISS_OK = 0
} kiss_ret_val;

#define KISS_ASSERT assertCondCFmt
#define KISS_ASSERT_CRASH assertCondCFmt

#define FW_KMEM_SLEEP 0

#define herror(a, b, ...)

#define kdprintf printf
#define kdprintf_no_prefix printf


void fw_kfree(void *addr, size_t size, const char *caller);
void *fw_kmalloc(size_t size, const char *caller);
void *fw_kmalloc_ex(size_t size, const char *caller, int flags);
void *fw_kmalloc_sleep(size_t size, const char *caller);
void *kiss_pmglob_memory_kmalloc_ex_(u_int size, const char *caller, int flags, const char *file, int line);
void *kiss_pmglob_memory_kmalloc_ex(u_int size, const char *caller, int flags);
void *kiss_pmglob_memory_kmalloc(u_int size, const char *caller);
void kiss_pmglob_memory_kfree(void *addr, size_t size, const char *caller);

#define ENUM_SET_FLAG(e, flag) e = static_cast<decltype(e)>(((u_int)e | (u_int)flag))
#define ENUM_UNSET_FLAG(e, flag) e = static_cast<decltype(e)>(((u_int)e & (~(u_int)flag)))

#define MAX(x, y) (((x)>(y))?(x):(y))
#define MIN(x, y) (((x)<(y))?(x):(y))


#endif // __general_adaptor_h__
