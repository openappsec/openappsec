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

#include "WaapOverride.h"

USE_DEBUG_FLAG(D_WAAP);

namespace Waap {
namespace Override {

bool Match::operator==(const Match &other) const
{
    return  (m_op == other.m_op) &&
            (m_operand1 == other.m_operand1) &&
            (m_operand2 == other.m_operand2) &&
            (m_tag == other.m_tag) &&
            (m_valuesRegex == other.m_valuesRegex) &&
            m_ip_addr_values == other.m_ip_addr_values &&
            m_isCidr == other.m_isCidr;
}

Behavior::Behavior()
: m_id(""), m_action(""), m_log(""), m_sourceIdentifier("")
{
}

bool Behavior::operator==(const Behavior &other) const
{
    return  (m_action == other.m_action) && (m_log == other.m_log) && (m_sourceIdentifier == other.m_sourceIdentifier);
}

const std::string & Behavior::getParentId() const
{
    return m_id;
}

const std::string & Behavior::getAction() const
{
    return m_action;
}

const std::string& Behavior::getLog() const
{
    return m_log;
}

const std::string& Behavior::getSourceIdentifier() const
{
    return m_sourceIdentifier;
}

void Behavior::setParentId(const std::string& id)
{
    m_id = id;
}

bool Rule::operator==(const Rule &other) const
{
    return  (m_match == other.m_match) &&
            (m_isChangingRequestData == other.m_isChangingRequestData) &&
            (m_behaviors == other.m_behaviors);
}

bool Policy::operator==(const Policy &other) const
{
    return m_RequestOverrides == other.m_RequestOverrides &&
        m_ResponseOverrides == other.m_ResponseOverrides;
}

State::State() :
    bForceBlock(false),
    forceBlockIds(),
    bForceException(false),
    forceExceptionIds(),
    bSupressLog(false),
    bSourceIdentifierOverride(false),
    sSourceIdentifierMatch("")
{
}

bool ExceptionsByPractice::operator==(const ExceptionsByPractice &other) const
{
    return m_web_app_ids == other.m_web_app_ids &&
        m_api_protect_ids == other.m_api_protect_ids &&
        m_anti_bot_ids == other.m_anti_bot_ids;
}

const std::vector<std::string>& ExceptionsByPractice::getExceptionsOfPractice(DecisionType practiceType) const
{
    switch (practiceType)
    {

    case DecisionType::AUTONOMOUS_SECURITY_DECISION:
        return m_web_app_ids;
    default:
        dbgError(D_WAAP) <<
        "Can't find practice type for exceptions by practice: " <<
        practiceType <<
        ", return web app exceptions";
        return m_web_app_ids;
    }
}

const std::set<std::string>& ExceptionsByPractice::getAllExceptions() const
{
    return m_all_ids;
}

bool ExceptionsByPractice::isIDInWebApp(const std::string &id) const
{
    auto it = std::find(m_web_app_ids.begin(), m_web_app_ids.end(), id);
    if (it != m_web_app_ids.end()) {
        dbgTrace(D_WAAP) << "rule id is in web application exceptions by practice: " << id;
        return true;
    }
    return false;
}
}
}
