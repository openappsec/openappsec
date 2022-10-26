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

#pragma once
#include <vector>
#include <map>
#include <string>
#include <unordered_set>
#include <boost/noncopyable.hpp>
#include <cereal/types/map.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/memory.hpp>

#include "i_serialize.h"

#define FP_SCORE_CALCULATION_INTERVALS 20

enum PolicyCounterType {
    UNKNOWN_TYPE = 0,
    FALSE_POSITIVE,
    HTML_CONTENT,
    TRUE_POSITIVE,
    SPAM
};

class PolicyDataCounter {
public:
    PolicyDataCounter();

    double getScore();

    void incrementCounter(PolicyCounterType counterType);
    void evaluateScore();

    bool operator==(PolicyDataCounter& other);
    bool operator!=(PolicyDataCounter& other) { return !(*this == other); }

    template <class Archive>
    void serialize(Archive& ar) {
        ar(cereal::make_nvp("falsePositive", falsePositive),
            cereal::make_nvp("truePositive", truePositive),
            cereal::make_nvp("score", score));
    }
private:
    size_t falsePositive;
    size_t truePositive;
    double score;
};

class FpMitigationScore : public boost::noncopyable, public SerializeToFilePeriodically {
public:
    FpMitigationScore(const std::string& backupFilePath);
    ~FpMitigationScore();

    double calculateFpMitigationScore(const std::string& shortUri, const std::string& canonisedParam);
    void learnFalsePositive(const std::vector<std::string>& keywordMatches, PolicyCounterType rep,
        const std::string& shortUri, const std::string& canonisedParam);
    PolicyCounterType IdentifyFalseTruePositive(double relativeReputation, const std::string& shortUri,
        const std::string& canonisedParam, const std::string& userAgentIp);

    void reset();

    virtual void serialize(std::ostream& stream);
    virtual void deserialize(std::istream& stream);

    typedef std::map<std::string, std::shared_ptr<PolicyDataCounter>> PolicyDataMap;

protected:

    void incrementCounter(const std::string& shortUri, const std::string& canonisedParam,
        PolicyCounterType counterType);
    void evaluatePolicyDataCounterScore();


    // TODO: move to SMEM
    PolicyDataMap m_policyDataUrl;
    PolicyDataMap m_policyDataParam;
    std::unordered_set<std::string> m_history;
    size_t m_counter;
};
