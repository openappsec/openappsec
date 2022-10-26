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

#ifndef __WAAP_SAMPLE_VALUE_H__
#define __WAAP_SAMPLE_VALUE_H__

#include <memory>
#include <vector>
#include <string>
#include "Waf2Regex.h"
#include "WaapRegexPreconditions.h"
#include "buffer.h"

class SampleValue
{
public:
    SampleValue(const std::string &sample, const std::shared_ptr<Waap::RegexPreconditions> &regexPreconditions);
    const std::string &getSampleString() const;
    void findMatches(const Regex &pattern, std::vector<RegexMatch> &matches) const;

private:
    std::string m_sample;
    const std::shared_ptr<Waap::RegexPreconditions> m_regexPreconditions;
    Waap::RegexPreconditions::PmWordSet m_pmWordSet;
};

#endif // __WAAP_SAMPLE_VALUE_H__
