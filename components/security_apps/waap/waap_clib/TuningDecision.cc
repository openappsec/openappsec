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

using namespace std;

static const string defaultSharedStorageHost = "appsec-shared-storage-svc";

#define SHARED_STORAGE_HOST_ENV_NAME "SHARED_STORAGE_HOST"
USE_DEBUG_FLAG(D_WAAP);

TuningDecision::TuningDecision(const string& remotePath)
        :
    m_remotePath(remotePath + "/tuning"),
    m_baseUri()
{
    if (remotePath == "")
    {
        return;
    }
    Singleton::Consume<I_MainLoop>::by<WaapComponent>()->addRecurringRoutine(
        I_MainLoop::RoutineType::System,
        chrono::minutes(10),
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
    string decision;
    string eventType;
    string eventTitle;
};

class TuningEvents : public RestGetFile
{
public:
    TuningEvents()
    {

    }

    Maybe<vector<TuningEvent>> getTuningEvents()
    {
        return decisions.get();
    }

private:
    S2C_PARAM(vector<TuningEvent>, decisions);
};

TuningDecisionEnum TuningDecision::convertDecision(string decisionStr)
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

TuningDecisionType TuningDecision::convertDecisionType(string decisionTypeStr)
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
    I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
    if (agentDetails->getOrchestrationMode() != OrchestrationMode::ONLINE) {
        m_baseUri = "/api/";
    } else {
        m_baseUri = "/storage/waap/";
    }
    dbgTrace(D_WAAP) << "URI prefix: " << m_baseUri;
    bool isSuccessful = sendObject(tuningDecisionFiles,
        I_Messaging::Method::GET,
        m_baseUri + "?list-type=2&prefix=" + m_remotePath);

    if (!isSuccessful || tuningDecisionFiles.getFilesList().empty())
    {
        dbgDebug(D_WAAP) << "Failed to get the list of files";
        return;
    }

    if (!sendObject(tuningEvents,
        I_Messaging::Method::GET,
        m_baseUri + tuningDecisionFiles.getFilesList()[0]))
    {
        return;
    }
    m_decisions.clear();
    Maybe<vector<TuningEvent>> events = tuningEvents.getTuningEvents();
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

TuningDecisionEnum TuningDecision::getDecision(string tuningValue, TuningDecisionType tuningType)
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

string
TuningDecision::getSharedStorageHost()
{
    static string shared_storage_host;
    if (!shared_storage_host.empty()) {
        return shared_storage_host;
    }
    char* sharedStorageHost = getenv(SHARED_STORAGE_HOST_ENV_NAME);
    if (sharedStorageHost != NULL) {
        shared_storage_host = string(sharedStorageHost);
        dbgInfo(D_WAAP) << "shared storage host is set to " << shared_storage_host;
        return shared_storage_host;
    }
    dbgWarning(D_WAAP) << "shared storage host is not set. using default: " << defaultSharedStorageHost;
    return defaultSharedStorageHost;
}
