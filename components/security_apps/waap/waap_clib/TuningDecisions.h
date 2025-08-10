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

#ifndef __TUNING_DECISIONS_H__
#define __TUNING_DECISIONS_H__

#include <string>
#include <map>
#include "i_messaging.h"
#include "i_agent_details.h"
#include "waap.h"

enum TuningDecisionEnum
{
    NO_DECISION,
    DISMISS = NO_DECISION,
    BENIGN,
    MALICIOUS
};

enum TuningDecisionType
{
    UNKNOWN,
    SOURCE,
    URL,
    PARAM_NAME,
    PARAM_VALUE
};


class TuningDecision
{
public:
    TuningDecision(const std::string& remotePath);
    ~TuningDecision();

    TuningDecisionEnum getDecision(std::string tuningValue, TuningDecisionType tuningType);
private:
    void updateDecisions();
    TuningDecisionType convertDecisionType(std::string decisionTypeStr);
    TuningDecisionEnum convertDecision(std::string decisionStr);
    std::string getSharedStorageHost();

    template<typename T>
    bool sendObject(T &obj, HTTPMethod method, std::string uri)
    {
        I_Messaging *messaging = Singleton::Consume<I_Messaging>::by<WaapComponent>();
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<WaapComponent>();
        if (agentDetails->getOrchestrationMode() != OrchestrationMode::ONLINE) {
            MessageMetadata req_md(getSharedStorageHost(), 80);
            req_md.insertHeader("X-Tenant-Id", agentDetails->getTenantId());
            req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
            req_md.setConnectioFlag(MessageConnectionConfig::ONE_TIME_CONN);
            auto req_status = messaging->sendSyncMessage(
                method,
                uri,
                obj,
                MessageCategory::GENERIC,
                req_md
            );
            return req_status.ok();
        }
        MessageMetadata req_md;
        req_md.setConnectioFlag(MessageConnectionConfig::ONE_TIME_FOG_CONN);
        auto req_status = messaging->sendSyncMessage(
            method,
            uri,
            obj,
            MessageCategory::GENERIC,
            req_md
        );
        return req_status.ok();
    }

    std::string m_remotePath;
    std::string m_baseUri;
    std::map<TuningDecisionType, std::map<std::string, TuningDecisionEnum>> m_decisions;
};

#endif
