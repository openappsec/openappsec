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

#ifndef __SINGLE_DECISION_H__
#define __SINGLE_DECISION_H__

#include "DecisionType.h"
#include <string>

class SingleDecision
{
public:
    explicit SingleDecision(DecisionType type);
    virtual ~SingleDecision();

    void setLog(bool log);
    void setBlock(bool block);
    DecisionType getType() const;
    bool shouldLog() const;
    bool shouldBlock() const;
    virtual std::string getTypeStr() const = 0;

protected:
    DecisionType m_type;
    bool m_log;
    bool m_block;
};

#endif
