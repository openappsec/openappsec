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

#include "pm_hook.h"
#include <ctype.h>
#include <stdlib.h>
#include <fstream>
#include <algorithm>
#include <string>
#include <unordered_map>
#include "kiss_patterns.h"
#include "kiss_thin_nfa_impl.h"

using namespace std;

USE_DEBUG_FLAG(D_PM_COMP);
USE_DEBUG_FLAG(D_PM_EXEC);
USE_DEBUG_FLAG(D_PM);

static int
pm_pattern_to_kiss_pat_flags(const PMPattern &pat)
{
    int kiss_pat_flags = 0;
    if (pat.isStartMatch()) {
        kiss_pat_flags |= KISS_PM_LSS_AT_BUF_START;
    }
    if (pat.isEndMatch()) {
        kiss_pat_flags |= KISS_PM_LSS_AT_BUF_END;
    }
    return kiss_pat_flags;
}


static list<kiss_pmglob_string_s>
convert_patt_map_to_kiss_list(const map<int, PMPattern> &patt_map)
{
    list<kiss_pmglob_string_s> kiss_pats;
    for (auto &pair : patt_map) {
        auto &id = pair.first;
        auto &pattern = pair.second;
        kiss_pats.emplace_back(pattern.data(), pattern.size(), id, pm_pattern_to_kiss_pat_flags(pattern));
    }
    return kiss_pats;
}

// Explicit empty ctor and dtor needed due to incomplete definition of class used in unique_ptr. Bummer...
PMHook::PMHook()
{
}

PMHook::~PMHook()
{
}

Maybe<PMPattern>
PMHook::lineToPattern(const string &line)
{
    if (line.empty()) return genError("Empty string");

    bool start = (*line.begin()) == '^';
    bool end = (*line.rbegin()) == '$';

    int start_offset = start ? 1 : 0;
    int line_size = line.size() - (start ? 1 : 0) - (end ? 1 : 0);
    auto clean_line = line.substr(start_offset, line_size);

    if (clean_line.empty()) return genError("Pattern must contain actual content");

    return PMPattern(clean_line, start, end);
}

Maybe<void>
PMHook::prepare(const set<PMPattern> &inputs)
{
    map<int, PMPattern> tmp;
    int index = 0;
    for (auto &pat : inputs) {
        tmp.emplace(++index, pat);
    }

    if (Debug::isFlagAtleastLevel(D_PM_COMP, Debug::DebugLevel::DEBUG)) kiss_debug_start();
    KissPMError pm_err;
    handle = kiss_thin_nfa_compile(convert_patt_map_to_kiss_list(tmp), KISS_PM_COMP_CASELESS, &pm_err);
    if (Debug::isFlagAtleastLevel(D_PM_COMP, Debug::DebugLevel::DEBUG)) kiss_debug_stop();

    if (handle == nullptr) {
        dbgError(D_PM_COMP) << "PMHook::prepare() failed" << pm_err;
        return genError(pm_err.error_string);
    }

    patterns = tmp;
    return Maybe<void>();
}

set<PMPattern>
PMHook::scanBuf(const Buffer &buf) const
{
    dbgAssert(handle != nullptr) << "Unusable Pattern Matcher";
    vector<pair<uint, uint>> pm_matches;
    kiss_thin_nfa_exec(handle.get(), buf, pm_matches);
    dbgTrace(D_PM) << pm_matches.size() << " raw matches found";

    set<PMPattern> res;
    for (auto &match : pm_matches) {
        res.insert(patterns.at(match.first));
    }
    dbgTrace(D_PM) << res.size() << " matches found after removing the duplicates";
    return res;
}

set<pair<uint, uint>>
PMHook::scanBufWithOffset(const Buffer &buf) const
{
    dbgAssert(handle != nullptr) << "Unusable Pattern Matcher";

    vector<pair<uint, uint>> pm_matches;
    kiss_thin_nfa_exec(handle.get(), buf, pm_matches);
    dbgTrace(D_PM) << pm_matches.size() << " raw matches found";

    set<pair<uint, uint>> res(pm_matches.begin(), pm_matches.end());
    dbgTrace(D_PM) << res.size() << " matches found";
    return res;
}

void
PMHook::scanBufWithOffsetLambda(const Buffer &buf, I_PMScan::CBFunction cb) const
{
    dbgAssert(handle != nullptr) << "Unusable Pattern Matcher";

    unordered_map<uint, uint> match_counts;
    vector<pair<uint, uint>> pm_matches;
    static const uint maxCbCount = 3;
    uint totalCount = 0;

    kiss_thin_nfa_exec(handle.get(), buf, pm_matches);
    dbgTrace(D_PM) << pm_matches.size() << " raw matches found";

    for (auto &res : pm_matches) {
        uint patIndex = res.first;
        uint cbCount = match_counts[patIndex];
        const PMPattern &pat = patterns.at(patIndex);
        bool noRegex = pat.isNoRegex();
        bool isShort = (pat.size() == 1);

        // Limit the max number of callback calls per precondition, unless it's used as a regex substitute
        // On the last callback call, make sure to add the pre/post-word associated preconditions
        if (noRegex || cbCount < maxCbCount) {
            bool matchAll = !noRegex && (cbCount == maxCbCount-1 || isShort);

            totalCount++;
            cb(res.second, pat, matchAll);

            if (matchAll)
                match_counts[patIndex] = maxCbCount;
            else
                match_counts[patIndex]++;
        }
    }

    dbgTrace(D_PM) << totalCount << " filtered matches found";
}

bool
PMPattern::operator<(const PMPattern &other) const
{
    if (pattern != other.pattern) return pattern < other.pattern;
    if (index != other.index) return index < other.index;
    return tie(match_start, match_end) < tie(other.match_start, other.match_end);
}
bool
PMPattern::operator==(const PMPattern &other) const
{
    return
        index == other.index &&
        pattern == other.pattern &&
        match_start == other.match_start &&
        match_end == other.match_end;
}
