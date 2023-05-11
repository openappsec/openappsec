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

#include "WaapSampleValue.h"

SampleValue::SampleValue(const std::string &sample,
    const std::shared_ptr<Waap::RegexPreconditions> &regexPreconditions)
    :
        m_sample(sample),
        m_regexPreconditions(regexPreconditions),
        m_pmWordSet()
{
    if (m_regexPreconditions) {
        // Run aho-corasick and related rules once the sample value is known.
        // The result pmWordSet is reused later for multiple calls to findMatches on the same sample.
        regexPreconditions->pmScan(
            Buffer(m_sample.data(), m_sample.size(), Buffer::MemoryType::STATIC), m_pmWordSet);
    }
}

const std::string &
SampleValue::getSampleString() const
{
    return m_sample;
}

void
SampleValue::findMatches(const Regex &pattern, std::vector<RegexMatch> &matches) const
{
    static const size_t maxMatchesPerSignature = 5;
    pattern.findAllMatches(m_sample, matches, m_regexPreconditions ? &m_pmWordSet : nullptr, maxMatchesPerSignature);
}
