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

#ifndef __PM_HOOK_H__
#define __PM_HOOK_H__

#include <memory>
#include <string>
#include <map>
#include <unordered_set>
#include <sys/types.h>
#include "i_pm_scan.h"

class KissThinNFA;

class PMHook final : public I_PMScan
{
public:
    explicit PMHook();
    ~PMHook();

    Maybe<void> prepare(const std::set<PMPattern> &patterns);
    std::set<PMPattern> scanBuf(const Buffer &buf) const override;
    std::set<std::pair<uint, uint>> scanBufWithOffset(const Buffer &buf) const override;
    void scanBufWithOffsetLambda(const Buffer &buf, I_PMScan::CBFunction cb) const override;

    // Line may begin with ^ or $ sign to mark LSS is at begin/end of buffer.
    static Maybe<PMPattern> lineToPattern(const std::string &line);
    bool ok() const { return static_cast<bool>(handle); }

private:
    std::shared_ptr<KissThinNFA> handle;
    std::map<int, PMPattern> patterns;
};

#endif // __PM_HOOK_H__
