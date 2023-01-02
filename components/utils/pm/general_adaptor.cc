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

#include "general_adaptor.h"
#include <stdlib.h>

void fw_kfree(void *addr, CP_MAYBE_UNUSED size_t size, CP_MAYBE_UNUSED const char *caller)
{
    free(addr);
    return;
}

void *fw_kmalloc(size_t size, CP_MAYBE_UNUSED const char *caller)
{
    return malloc(size);
}

void *fw_kmalloc_ex(size_t size, CP_MAYBE_UNUSED const char *caller, CP_MAYBE_UNUSED int flags)
{
    return malloc(size);
}

void *fw_kmalloc_sleep(size_t size, CP_MAYBE_UNUSED const char *caller)
{
    return malloc(size);
}

void *kiss_pmglob_memory_kmalloc_ex_(
    u_int size,
    CP_MAYBE_UNUSED const char *caller,
    CP_MAYBE_UNUSED int flags,
    CP_MAYBE_UNUSED const char *file,
    CP_MAYBE_UNUSED int line)
{
    return malloc(size);
}

void *kiss_pmglob_memory_kmalloc_ex(u_int size, CP_MAYBE_UNUSED const char *caller, CP_MAYBE_UNUSED int flags)
{
    return malloc(size);
}

void *kiss_pmglob_memory_kmalloc(u_int size, CP_MAYBE_UNUSED const char *caller)
{
    return malloc(size);
}

void kiss_pmglob_memory_kfree(void *addr, CP_MAYBE_UNUSED size_t size, CP_MAYBE_UNUSED const char *caller)
{
    free(addr);
    return;
}
