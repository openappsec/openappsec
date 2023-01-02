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

#include "debug.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>

using namespace std;

USE_DEBUG_FLAG(D_PM);

// Helper class for printing C format string
class CFmtPrinter
{
public:
    char buf[500];        // Length limit.
    explicit CFmtPrinter(const char *fmt, va_list va)
    {
        vsnprintf(buf, sizeof(buf), fmt, va);
        buf[sizeof(buf)-1] = '\0';
    }
};

static ostream &
operator<<(ostream &os, const CFmtPrinter &p)
{
    return os << p.buf;
}

void
panicCFmt(const string &func, uint line, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    Debug("PM", func, line).getStreamAggr() << CFmtPrinter(fmt, va);
    va_end(va);
}

void
debugPrtCFmt(const char *func, uint line, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    Debug("PM", func, line, Debug::DebugLevel::TRACE, D_PM).getStreamAggr() << CFmtPrinter(fmt, va);
    va_end(va);
}
