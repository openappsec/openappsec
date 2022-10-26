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

#include "WaapEnums.h"

struct DecisionTelemetryData
{
    BlockType blockType;
    ThreatLevel threat;
    std::string assetName;
    std::string practiceId;
    std::string practiceName;
    std::string source;
    std::set<std::string> attackTypes;

    DecisionTelemetryData() :
        blockType(NOT_BLOCKING),
        threat(NO_THREAT),
        assetName(),
        practiceId(),
        practiceName(),
        source(),
        attackTypes()
    {
    }
};

class I_Telemetry
{
public:
    virtual void logDecision(std::string assetId, DecisionTelemetryData& data) = 0;
protected:
    virtual ~I_Telemetry() {}
};
