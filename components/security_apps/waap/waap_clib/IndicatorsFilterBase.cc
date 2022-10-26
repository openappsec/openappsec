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

#include "i_indicatorsFilter.h"
#include "IndicatorsFilterBase.h"
#include "Waf2Engine.h"

IndicatorFilterBase::IndicatorFilterBase(const std::string& confidence_path,
    const std::string& trusted_path,
    const std::string& remotePath,
    const std::string& assetId,
    size_t min_sources,
    size_t min_intervals,
    std::chrono::minutes interval_duration,
    double ratio_threshold,
    const std::string& null_obj,
    TuningDecision* tuning,
    I_IgnoreSources* ignoreSources) :
    m_confidence_calc(min_sources,
        min_intervals,
        interval_duration,
        ratio_threshold,
        null_obj,
        confidence_path,
        remotePath,
        assetId,
        tuning,
        ignoreSources),
    m_trusted_confidence_calc(trusted_path, remotePath, assetId),
    m_policy(nullptr),
    m_tuning(tuning)
{

}

void IndicatorFilterBase::filterKeywords(
    const std::string &key,
    Waap::Keywords::KeywordsSet& keywords,
    std::vector<std::string>& filteredKeywords)
{
    for (auto keyword = keywords.begin(); keyword != keywords.end(); )
    {
        if (shouldFilterKeyword(key, *keyword))
        {
            filteredKeywords.push_back(*keyword);
            keyword = keywords.erase(keyword);
        }
        else
        {
            keyword++;
        }
    }
}

bool IndicatorFilterBase::setTrustedSrcParameter(
    std::shared_ptr<Waap::TrustedSources::TrustedSourcesParameter> policy)
{
    bool isChanged = false;
    if (m_policy != nullptr && *policy != *m_policy)
    {
        isChanged = true;
        m_trusted_confidence_calc.reset();
    }
    m_policy = policy;
    return isChanged;
}

void IndicatorFilterBase::reset()
{
    m_confidence_calc.hardReset();
    m_trusted_confidence_calc.reset();
}

bool IndicatorFilterBase::isTrustedSourceOfType(const std::string& source,
    Waap::TrustedSources::TrustedSourceType srcType)
{
    if (m_policy == nullptr)
    {
        dbgTrace(D_WAAP) << "missing policy";
        return false;
    }
    std::string trusted_src(source);
    if (srcType == Waap::TrustedSources::TrustedSourceType::X_FORWARDED_FOR)
    {
        auto env = Singleton::Consume<I_Environment>::by<WaapComponent>();
        auto proxy_ip = env->get<std::string>(HttpTransactionData::proxy_ip_ctx);
        if (proxy_ip.ok())
        {
            trusted_src = proxy_ip.unpack();
        } else{
            trusted_src = "";
        }
    }
    else if (srcType == Waap::TrustedSources::TrustedSourceType::COOKIE_OAUTH2_PROXY)
    {
        trusted_src = Waap::Util::extractKeyValueFromCookie(source, "_oauth2_proxy");
    }
    else if (srcType == Waap::TrustedSources::TrustedSourceType::SM_USER)
    {
        trusted_src = source;
    }
    return m_policy->isSourceTrusted(trusted_src, srcType);
}


std::string IndicatorFilterBase::getTrustedSource(IWaf2Transaction* pTransaction)
{
    if (m_policy == nullptr)
    {
        dbgTrace(D_WAAP) << "Policy for trusted sources is not set";
        return "";
    }
    auto trustedTypes = m_policy->getTrustedTypes();
    std::string xFwdVal;
    std::string cookieVal;
    std::string smuserVal;

    for (auto& trustedType : trustedTypes)
    {
        switch (trustedType)
        {
        case Waap::TrustedSources::TrustedSourceType::SOURCE_IP:
            if (isTrustedSourceOfType(pTransaction->getRemoteAddr(), trustedType))
            {
                return pTransaction->getRemoteAddr();
            }
            break;
        case Waap::TrustedSources::TrustedSourceType::X_FORWARDED_FOR:
            if (xFwdVal.empty())
            {
                xFwdVal = pTransaction->getHdrContent("X-Forwarded-For");
            }
            if (isTrustedSourceOfType(xFwdVal, trustedType))
            {
                return xFwdVal;
            }
            break;
        case Waap::TrustedSources::TrustedSourceType::SM_USER:
            if (smuserVal.empty())
            {
                smuserVal = pTransaction->getHdrContent("sm_user");
            }
            if (isTrustedSourceOfType(smuserVal, trustedType))
            {
                return smuserVal;
            }
            break;
        case Waap::TrustedSources::TrustedSourceType::COOKIE_OAUTH2_PROXY:
            if (cookieVal.empty())
            {
                cookieVal = pTransaction->getHdrContent("Cookie");
            }
            if (isTrustedSourceOfType(cookieVal, trustedType))
            {
                return cookieVal;
            }
            break;
        default:
            dbgWarning(D_WAAP) << "unrecognized trusted source identifier type: " << trustedType;
            break;
        }
    }

    return "";
}

void IndicatorFilterBase::registerKeyword(const std::string& key,
    const std::string& keyword,
    const std::string& source,
    const std::string& trusted_src)
{
    dbgTrace(D_WAAP) << "registering keyword: " << keyword << " for parameter: " << key << " from source: " << source;
    if (keyword == "probing" || keyword == "repetition")
    {
        dbgTrace(D_WAAP) << "ignoring keyword " << keyword;
        return;
    }
    m_confidence_calc.log(key, keyword, source);
    if (trusted_src != "")
    {
        m_trusted_confidence_calc.log(key, keyword, trusted_src);
    }
}
