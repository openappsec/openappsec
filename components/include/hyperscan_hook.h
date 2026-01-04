// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __HYPERSCAN_HOOK_H__
#define __HYPERSCAN_HOOK_H__

#ifdef USE_HYPERSCAN
#include <vector>
#include <string>

#include <set>
#include "hs.h"
#include "i_pm_scan.h"

class HyperscanHook : public I_PMScan {
public:
    HyperscanHook();
    ~HyperscanHook();
    Maybe<void> prepare(const std::set<PMPattern> &patterns);
    std::set<PMPattern> scanBuf(const Buffer &buf) const override;
    std::set<std::pair<uint, uint>> scanBufWithOffset(const Buffer &buf) const override;
    void scanBufWithOffsetLambda(const Buffer &buf, I_PMScan::CBFunction cb) const override;
    bool ok() const { return m_hsReady; }
private:
    hs_database_t *m_hsDatabase;
    hs_scratch_t *m_hsScratch;
    std::vector<std::string> m_hsPatterns;
    std::vector<PMPattern> m_idToPattern;
    bool m_hsReady;
};
#endif // USE_HYPERSCAN

#endif // __HYPERSCAN_HOOK_H__
