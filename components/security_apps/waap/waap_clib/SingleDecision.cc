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

#include "SingleDecision.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

SingleDecision::SingleDecision(DecisionType type):
    m_type(type),
    m_log(false),
    m_block(false)
{}

SingleDecision::~SingleDecision()
{}

DecisionType SingleDecision::getType() const
{
    return m_type;
}

bool SingleDecision::shouldLog() const
{
    return m_log;
}

bool SingleDecision::shouldBlock() const
{
    return m_block;
}

void SingleDecision::setLog(bool log)
{
    dbgTrace(D_WAAP) << "Decision " << getTypeStr() << " changes should log from " << m_log << " to " << log;
    m_log = log;
}

void SingleDecision::setBlock(bool block)
{
    dbgTrace(D_WAAP) << "Decision " << getTypeStr() << " changes should block  from " << m_block << " to " << block;
    m_block = block;
}
