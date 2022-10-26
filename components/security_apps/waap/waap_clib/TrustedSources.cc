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

#include <string>
#include <boost/regex.hpp>

#include "TrustedSources.h"
#include "Waf2Util.h"
#include "CidrMatch.h"
#include "agent_core_utilities.h"

using namespace Waap::TrustedSources;

TrustedSourcesParameter::TrustedSourcesParameter() : m_identifiers()
{

}

bool TrustedSourcesParameter::isSourceTrusted(std::string source, TrustedSourceType srcType)
{
    if (m_identifiers.empty())
    {
        return false;
    }

    if (source.empty())
    {
        return false;
    }
    switch (srcType)
    {
    case SOURCE_IP:
    case X_FORWARDED_FOR:
        return m_identifiers[0].isCidrMatch(source, srcType);
    case COOKIE_OAUTH2_PROXY:
        return m_identifiers[0].isRegexMatch(source, COOKIE_OAUTH2_PROXY);
    case SM_USER:
        return m_identifiers[0].isRegexMatch(source, SM_USER);
    case UNKNOWN:
        break;
    default:
        break;
    }
    return false;
}

size_t TrustedSourcesParameter::getNumOfSources()
{
    if (m_identifiers.empty())
    {
        return (size_t)(-1);
    }
    return m_identifiers[0].getNumOfSources();
}

std::set<Waap::TrustedSources::TrustedSourceType> Waap::TrustedSources::TrustedSourcesParameter::getTrustedTypes()
{
    if (m_identifiers.empty())
    {
        return std::set<TrustedSourceType>();
    }
    return m_identifiers[0].getTrustedTypes();
}


bool SourcesIdentifers::isCidrMatch(const std::string &source, const TrustedSourceType &trustedSourceType) const
{
    auto found = m_identifiersMap.find(trustedSourceType);
    if (found == m_identifiersMap.end())
    {
        return false;
    }
    const std::vector<std::string>& cidrs = found->second;
    for (auto cidr : cidrs)
    {
        if (Waap::Util::cidrMatch(source, cidr))
        {
            dbgTrace(D_WAAP) << "source: " << source << " is trusted for type: " << trustedSourceType <<
                ", cidr: " << cidr;
            return true;
        }
    }
    return false;
}

bool SourcesIdentifers::isRegexMatch(const std::string &source, const TrustedSourceType& type) const
{
    auto found = m_identifiersMap.find(type);
    if (found == m_identifiersMap.end())
    {
        return false;
    }
    const std::vector<std::string>& regexes = found->second;
    for (auto regex : regexes)
    {
        boost::regex expr{ regex };
        boost::smatch matches;
        if (NGEN::Regex::regexSearch(__FILE__, __LINE__, source, matches, expr))
        {
            dbgTrace(D_WAAP) << "source: " << source << " is trusted for type: " << type <<
                ", expr: " << regex;
            return true;
        }
    }
    return false;
}

size_t SourcesIdentifers::getNumOfSources() const
{
    return m_minSources;
}

const std::set<TrustedSourceType>& SourcesIdentifers::getTrustedTypes()
{
    return m_trustedTypes;
}


bool SourcesIdentifers::operator!=(const SourcesIdentifers& other) const
{
    if (m_identifiersMap.size() != other.m_identifiersMap.size())
    {
        return true;
    }
    if (m_minSources != other.m_minSources)
    {
        return true;
    }

    for (auto identifier : m_identifiersMap)
    {
        if (other.m_identifiersMap.find(identifier.first) == other.m_identifiersMap.end())
        {
            return true;
        }
        TrustedSourceType currType = identifier.first;
        const std::vector<std::string>& values = identifier.second;
        std::vector<std::string> otherValues = other.m_identifiersMap.at(currType);
        if (values.size() != otherValues.size())
        {
            return true;
        }
        for (size_t i = 0; i < values.size(); i++)
        {
            if (values[i] != otherValues[i])
            {
                return true;
            }
        }
    }

    return false;
}


Identifer::Identifer() : identitySource(UNKNOWN), value()
{
}

TrustedSourceType Identifer::convertSourceIdentifierToEnum(std::string identifierType)
{
    static const std::string SourceIp = "Source IP";
    static const std::string cookie = "Cookie:_oauth2_proxy";
    static const std::string smUser = "Header:sm_user";
    static const std::string forwrded = "X-Forwarded-For";
    if (memcaseinsensitivecmp(identifierType.c_str(), identifierType.size(), SourceIp.c_str(), SourceIp.size()))
    {
        return SOURCE_IP;
    }
    if (memcaseinsensitivecmp(identifierType.c_str(), identifierType.size(), cookie.c_str(), cookie.size()))
    {
        return COOKIE_OAUTH2_PROXY;
    }
    if (memcaseinsensitivecmp(identifierType.c_str(), identifierType.size(), forwrded.c_str(), forwrded.size()))
    {
        return X_FORWARDED_FOR;
    }
    if (memcaseinsensitivecmp(identifierType.c_str(), identifierType.size(), smUser.c_str(), smUser.size()))
    {
        return SM_USER;
    }
    dbgTrace(D_WAAP) << identifierType << " is not a recognized identifier type";
    return UNKNOWN;
}

bool TrustedSourcesParameter::operator==(const TrustedSourcesParameter &other) const
{
    return !(*this != other);
}

bool TrustedSourcesParameter::operator!=(const TrustedSourcesParameter& other) const
{
    if (m_identifiers.size() != other.m_identifiers.size())
    {
        return true;
    }

    for (size_t i = 0; i < m_identifiers.size(); i++)
    {
        if (m_identifiers[i] != other.m_identifiers[i])
        {
            return true;
        }
    }

    return false;
}
