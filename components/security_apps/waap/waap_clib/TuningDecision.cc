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

#include "TuningDecisions.h"
#include "i_mainloop.h"
#include "i_serialize.h"
#include "waap.h"

static const std::string BASE_URI = "/storage/waap/";
USE_DEBUG_FLAG(D_WAAP);

TuningDecision::TuningDecision(const std::string& remotePath) :
    m_remotePath(remotePath + "/tuning")
{
    if (remotePath == "")
    {
        return;
    }
    Singleton::Consume<I_MainLoop>::by<WaapComponent>()->addRecurringRoutine(
        I_MainLoop::RoutineType::System,
        std::chrono::minutes(10),
        [&]() { updateDecisions(); },
        "Get tuning updates"
    );
}

TuningDecision::~TuningDecision()
{

}

struct TuningEvent
{
    template<class Archive>
    void serialize(Archive& ar)
    {
        ar(cereal::make_nvp("decision", decision));
        ar(cereal::make_nvp("eventType", eventType));
        ar(cereal::make_nvp("eventTitle", eventTitle));
    }
    std::string decision;
    std::string eventType;
    std::string eventTitle;
};

class TuningEvents : public RestGetFile
{
public:
    TuningEvents()
    {

    }

    Maybe<std::vector<TuningEvent>> getTuningEvents()
    {
        return decisions.get();
    }

private:
    S2C_PARAM(std::vector<TuningEvent>, decisions);
};

TuningDecisionEnum TuningDecision::convertDecision(std::string decisionStr)
{
    if (decisionStr == "benign")
    {
        return BENIGN;
    }
    if (decisionStr == "malicious")
    {
        return MALICIOUS;
    }
    if (decisionStr == "dismiss")
    {
        return DISMISS;
    }
    return NO_DECISION;
}

TuningDecisionType TuningDecision::convertDecisionType(std::string decisionTypeStr)
{
    if (decisionTypeStr == "source")
    {
        return TuningDecisionType::SOURCE;
    }
    if (decisionTypeStr == "url")
    {
        return TuningDecisionType::URL;
    }
    if (decisionTypeStr == "parameterName")
    {
        return TuningDecisionType::PARAM_NAME;
    }
    if (decisionTypeStr == "parameterValue")
    {
        return TuningDecisionType::PARAM_VALUE;
    }
    return TuningDecisionType::UNKNOWN;
}

void TuningDecision::updateDecisions()
{
    TuningEvents tuningEvents;
    RemoteFilesList tuningDecisionFiles;
    bool isSuccessful = sendObject(tuningDecisionFiles,
        I_Messaging::Method::GET,
        BASE_URI + "?list-type=2&prefix=" + m_remotePath);

    if (!isSuccessful || tuningDecisionFiles.getFilesList().empty())
    {
        dbgDebug(D_WAAP) << "Failed to get the list of files";
        return;
    }

    if (!sendObject(tuningEvents,
        I_Messaging::Method::GET,
        BASE_URI + tuningDecisionFiles.getFilesList()[0]))
    {
        return;
    }
    m_decisions.clear();
    Maybe<std::vector<TuningEvent>> events = tuningEvents.getTuningEvents();
    if (!events.ok())
    {
        dbgDebug(D_WAAP) << "failed to parse events";
        return;
    }
    for (const auto& tEvent : events.unpack())
    {
        TuningDecisionType type = convertDecisionType(tEvent.eventType);
        m_decisions[type][tEvent.eventTitle] = convertDecision(tEvent.decision);
    }
}

TuningDecisionEnum TuningDecision::getDecision(std::string tuningValue, TuningDecisionType tuningType)
{
    const auto& typeDecisionsItr = m_decisions.find(tuningType);
    if (typeDecisionsItr == m_decisions.cend())
    {
        return NO_DECISION;
    }
    const auto& decisionItr = typeDecisionsItr->second.find(tuningValue);
    if (decisionItr == typeDecisionsItr->second.cend())
    {
        return NO_DECISION;
    }
    return decisionItr->second;
}
