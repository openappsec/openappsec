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

#include "FpMitigation.h"
#include <memory>
#include <algorithm>
#include <string.h>


#define DEFAULT_SCORE 10.0
#define TRUE_POSITIVE_REPUTATION_THRESHOLD 1.5
#define FALSE_POSITIVE_REPUTATION_THRESHOLD 5

USE_DEBUG_FLAG(D_WAAP);

using namespace std::chrono;

FpMitigationScore::FpMitigationScore(const std::string& backupFilePath) :
    SerializeToFilePeriodically(duration_cast<seconds>(minutes(10)), backupFilePath),
    m_policyDataUrl(),
    m_policyDataParam(),
    m_history(),
    m_counter(0)
{
    dbgTrace(D_WAAP) << "False positive mitigation constructor";
    restore();
}

FpMitigationScore::~FpMitigationScore()
{
    reset();
}

void FpMitigationScore::reset() {
    m_policyDataParam.clear();

    m_policyDataUrl.clear();

    m_history.clear();
}

void FpMitigationScore::serialize(std::ostream& stream) {
    cereal::JSONOutputArchive archive(stream);

    archive(cereal::make_nvp("version", 1),
        cereal::make_nvp("policyDataUrl", m_policyDataUrl),
        cereal::make_nvp("policyDataParam", m_policyDataParam));
}

void FpMitigationScore::deserialize(std::istream& stream) {
    cereal::JSONInputArchive archive(stream);

    size_t version = 0;

    try
    {
        archive(cereal::make_nvp("version", version));
    }
    catch (std::runtime_error & e) {
        archive.setNextName(nullptr);
        version = 0;
        dbgDebug(D_WAAP) << "Can't load file version: " << e.what();
    }

    switch (version)
    {
    case 0:
        archive(cereal::make_nvp("m_policyDataUrl", m_policyDataUrl),
            cereal::make_nvp("m_policyDataParam", m_policyDataParam));
        break;
    case 1:
        archive(cereal::make_nvp("policyDataUrl", m_policyDataUrl),
            cereal::make_nvp("policyDataParam", m_policyDataParam));
        break;
    default:
        dbgWarning(D_WAAP) << "unknown file format version: " << version;
        break;
    }
}


double FpMitigationScore::calculateFpMitigationScore(const std::string& shortUri,
    const std::string& canonisedParam)
{
    double urlScore = DEFAULT_SCORE, paramScore = DEFAULT_SCORE;

    if (m_policyDataUrl.find(shortUri) != m_policyDataUrl.end())
    {
        urlScore = m_policyDataUrl[shortUri]->getScore();
    }

    if (m_policyDataParam.find(canonisedParam) != m_policyDataParam.end())
    {
        paramScore = m_policyDataParam[canonisedParam]->getScore();
    }

    return ((int)(paramScore * 2) / 3 + 3.3) * ((int)(urlScore * 2) / 3 + 3.3) / 10;
}

template<typename T>
bool hasElement(std::vector<T> vec, T& elem) {
    return (std::find(vec.begin(), vec.end(), elem) != vec.end());
}

void FpMitigationScore::learnFalsePositive(
    const std::vector<std::string>& keywordMatches,
    PolicyCounterType rep,
    const std::string& shortUri,
    const std::string& canonisedParam)
{
    static std::string probing = "probing";

    if (keywordMatches.size() > 3 && hasElement(keywordMatches, probing))
    {
        return;
    }
    if (rep != UNKNOWN_TYPE)
    {
        if (m_policyDataUrl.find(shortUri) == m_policyDataUrl.end())
        {
            m_policyDataUrl[shortUri] = std::make_shared<PolicyDataCounter>();
        }
        if (m_policyDataParam.find(canonisedParam) == m_policyDataParam.end())
        {
            m_policyDataParam[canonisedParam] = std::make_shared<PolicyDataCounter>();
        }

        incrementCounter(shortUri, canonisedParam, rep);
        m_counter++;

        if (m_counter % FP_SCORE_CALCULATION_INTERVALS == 0)
        {
            dbgTrace(D_WAAP) << "evaluating fp mitigation scores";
            evaluatePolicyDataCounterScore();
        }
    }

}


PolicyCounterType FpMitigationScore::IdentifyFalseTruePositive(double relativeReputation,
    const std::string& shortUri, const std::string& canonisedParam, const std::string& userAgentIp)
{
    std::string uriParamCat = shortUri + canonisedParam;
    if (relativeReputation < TRUE_POSITIVE_REPUTATION_THRESHOLD && m_history.find(uriParamCat) == m_history.end())
    {
        m_history.insert(uriParamCat);
        return TRUE_POSITIVE;
    }
    if (relativeReputation > FALSE_POSITIVE_REPUTATION_THRESHOLD && m_history.find(userAgentIp) == m_history.end())
    {
        m_history.insert(userAgentIp);
        return FALSE_POSITIVE;
    }

    return UNKNOWN_TYPE;
}

void FpMitigationScore::incrementCounter(const std::string& shortUri,
    const std::string& canonisedParam,
    PolicyCounterType counterType)
{
    // It is assumed that m_policyDataUrl contains shortUrl and
    // m_policyDataParam contains canonisedParam. See caller.
    std::shared_ptr<PolicyDataCounter> urlCounter = m_policyDataUrl[shortUri];
    std::shared_ptr<PolicyDataCounter> paramCounter = m_policyDataParam[canonisedParam];

    urlCounter->incrementCounter(counterType);
    paramCounter->incrementCounter(counterType);
}

void FpMitigationScore::evaluatePolicyDataCounterScore()
{
    for (auto urlPolicy : m_policyDataUrl) {
        urlPolicy.second->evaluateScore();
    }

    for (auto paramPolicy : m_policyDataParam) {
        paramPolicy.second->evaluateScore();
    }
}

PolicyDataCounter::PolicyDataCounter() : falsePositive(0), truePositive(0), score(10.0)
{
}

double PolicyDataCounter::getScore()
{
    return score;
}

void PolicyDataCounter::incrementCounter(PolicyCounterType counterType)
{
    switch (counterType)
    {
    case UNKNOWN_TYPE:
        // add assert
        break;
    case FALSE_POSITIVE:
    case HTML_CONTENT:
        falsePositive++;
        break;
    case TRUE_POSITIVE:
    case SPAM:
        truePositive++;
        break;
    default:
        break;
    }
}

void PolicyDataCounter::evaluateScore()
{
    size_t tp = truePositive + 50 + 1, fp = falsePositive;
    score = (double)(10.0 * tp) / (10.0 * fp + tp);
}
