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

#ifndef __FILTER_VERDICT_H__
#define __FILTER_VERDICT_H__

#include <memory>

#include "maybe_res.h"
#include "i_http_event_impl.h"

class FilterVerdict
{
public:
    FilterVerdict(ngx_http_cp_verdict_e _verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT)
            :
        verdict(_verdict)
    {}

    FilterVerdict(const EventVerdict &_verdict, ModifiedChunkIndex _event_idx = -1)
            :
        verdict(_verdict.getVerdict())
    {
        if (verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT) {
            addModifications(_verdict.getModifications(), _event_idx);
        }
    }

    void
    addModifications(const FilterVerdict &other)
    {
        if (other.verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INJECT) return;

        modifications.insert(modifications.end(), other.modifications.begin(), other.modifications.end());
        total_modifications += other.total_modifications;
    }

    void
    addModifications(
        const ModificationList &mods,
        ModifiedChunkIndex _event_idx,
        ngx_http_cp_verdict_e alt_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT)
    {
        total_modifications += mods.size();
        modifications.push_back(EventModifications(_event_idx, mods));
        if (alt_verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT) verdict = alt_verdict;
    }

    uint getModificationsAmount() const { return total_modifications; }
    ngx_http_cp_verdict_e getVerdict() const { return verdict; }
    const std::vector<EventModifications> & getModifications() const { return modifications; }

private:
    ngx_http_cp_verdict_e verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    std::vector<EventModifications> modifications;
    uint total_modifications = 0;
};

#endif // __FILTER_VERDICT_H__
