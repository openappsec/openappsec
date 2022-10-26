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

#ifndef __REPORT_BULKS_H__
#define __REPORT_BULKS_H__

#include <queue>

#include "log_rest.h"

USE_DEBUG_FLAG(D_REPORT_BULK);

class ReportsBulk
{
public:
    void
    setBulkSize(uint size)
    {
        dbgAssert(size > 0) << "Bulk size must be larger than 0";
        dbgDebug(D_REPORT_BULK) << "Bulk size is set to " << size;
        bulk_size = size;
    }

    void
    push(Report &&report)
    {
        if (bulks.empty() || bulks.back().isFull()) {
            dbgDebug(D_REPORT_BULK) << "Adding a new bulk to queue";
            bulks.push(LogBulkRest(bulk_size));
        }
        bulks.back().push(std::move(report));
        ++elem_in_quque;
    }

    void
    push(const Report &report) {
        if (bulks.empty() || bulks.back().isFull()) {
            dbgDebug(D_REPORT_BULK) << "Adding a new bulk to queue";
            bulks.push(LogBulkRest(bulk_size));;
        }
        bulks.back().push(report);
        ++elem_in_quque;
    }

    LogBulkRest
    pop()
    {
        if (bulks.empty()) return LogBulkRest();
        dbgDebug(D_REPORT_BULK) << "Removing a bulk from queue";
        LogBulkRest res = std::move(bulks.front());
        bulks.pop();
        elem_in_quque -= res.size();
        return res;
    }

    void
    clear()
    {
        std::queue<LogBulkRest> empty;
        bulks.swap(empty);
        elem_in_quque = 0;
    }

    uint sizeQueue() const { return bulks.size(); }
    uint size() const { return elem_in_quque; }
    bool empty() const { return elem_in_quque == 0; }

private:
    std::queue<LogBulkRest> bulks;
    uint bulk_size = 100;
    uint elem_in_quque = 0;
};

#endif // __REPORT_BULKS_H__
