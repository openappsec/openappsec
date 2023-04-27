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

#include "agent_details_report.h"

#include <string>

using namespace std;

AgentDataReport::~AgentDataReport()
{
    if (!should_report) return;
    Singleton::Consume<I_AgentDetailsReporter>::by<AgentDataReport>()->sendReport(
        agent_details,
        policy_version,
        platform,
        architecture,
        agent_version
    );
}

AgentDataReport &
AgentDataReport::operator<<(const pair<string, string> &data)
{
    agent_details << data;
    return *this;
}

bool
AgentDataReport::operator==(const AgentDataReport &other) const
{
    return policy_version == other.policy_version &&
        platform == other.platform &&
        architecture == other.architecture &&
        agent_version  == other.agent_version &&
        agent_details == other.agent_details &&
        attributes == other.attributes;
}

void
AgentDataReport::setPolicyVersion(const string &_policy_version)
{
    policy_version = _policy_version;
}

void
AgentDataReport::setPlatform(const string &_platform)
{
    platform = _platform;
}

void
AgentDataReport::setArchitecture(const string &_architecture)
{
    architecture = _architecture;
}

void
AgentDataReport::setAgentVersion(const string &_agent_version)
{
    agent_version = _agent_version;
}

void
AgentDataReport::disableReportSending()
{
    should_report = false;
}
