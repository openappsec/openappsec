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

#ifndef __I_PM_SCAN_H__
#define __I_PM_SCAN_H__

#include <sys/types.h>
#include <set>
#include <iostream>
#include <functional>

#include "buffer.h"
#include "maybe_res.h"

class PMPattern
{
public:
    PMPattern() {}
    PMPattern(const std::string &pat, bool start, bool end, uint index = 0)
            :
        pattern(pat),
        match_start(start),
        match_end(end),
        index(index)
    {}

    bool operator<(const PMPattern &other) const;
    bool operator==(const PMPattern &other) const;

    bool isStartMatch() const { return match_start; }
    bool isEndMatch() const { return match_end; }
    const unsigned char * data() const { return reinterpret_cast<const unsigned char *>(pattern.data()); }
    size_t size() const { return pattern.size(); }
    bool empty() const { return pattern.empty(); }
    uint getIndex() const { return index; }

private:
    std::string pattern;
    bool match_start = false;
    bool match_end = false;
    uint index;
};

class I_PMScan
{
public:
    using CBFunction =  std::function<void(uint, const PMPattern &)>;

    virtual std::set<PMPattern> scanBuf(const Buffer &buf) const = 0;
    virtual std::set<std::pair<uint, PMPattern>> scanBufWithOffset(const Buffer &buf) const = 0;
    virtual void scanBufWithOffsetLambda(const Buffer &buf, CBFunction cb) const = 0;

protected:
    ~I_PMScan() {}
};

#endif // __I_PM_SCAN_H__
