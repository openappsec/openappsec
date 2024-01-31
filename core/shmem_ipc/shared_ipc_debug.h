// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __SHARED_IPC_DEBUG_H__
#define __SHARED_IPC_DEBUG_H__

extern void (*debug_int)(int is_error, const char *func, const char *file, int line_num, const char *fmt, ...);

#ifndef __FILENAME__
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

enum debugLevel { TraceLevel = 0, DebugLevel = 1, WarningLevel = 3 };

#define writeDebug(debug_level, fmt, ...)                                             \
    {                                                                                 \
        debug_int(debug_level, __func__, __FILENAME__, __LINE__, fmt, ##__VA_ARGS__); \
    }

#endif // __SHARED_IPC_DEBUG_H__
