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

#ifndef __DEBUGPM_H__
#define __DEBUGPM_H__

#include <iostream>
#include <string>

#include "debug.h"

// Assertions

// C-style BC functions (e.g. for PM).
void debugPrtCFmt(const std::string &func, uint line, const char *fmt, ...) __attribute__((format (printf, 3, 4)));
#define debugCFmt(flag, fmt, ...)                                \
    if (!Debug::isDebugSet(flag))                                \
    {                                                            \
    } else                                                       \
        debugPrtCFmt(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

void panicCFmt(const std::string &func, uint line, const char *fmt, ...) __attribute__((format (printf, 3, 4)));
#define assertCondCFmt(cond, fmt, ...)                         \
    if (CP_LIKELY(cond))                                       \
    {                                                          \
    } else                                                     \
        panicCFmt(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)

#endif // __DEBUGPM_H__
