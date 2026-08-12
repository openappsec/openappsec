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

#include "ParserDefaultSpecial.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER);

const std::string ParserDefaultSpecial::m_parserName = "ParserDefaultSpecial";

ParserDefaultSpecial::ParserDefaultSpecial(IParserStreamReceiver &receiver, size_t parser_depth)
    : m_receiver(receiver), m_error(false)
{
    dbgTrace(D_WAAP_PARSER) << "ParserDefaultSpecial constructed at depth " << parser_depth;
}

ParserDefaultSpecial::~ParserDefaultSpecial() {}

size_t ParserDefaultSpecial::push(const char *buf, size_t len)
{
    // Consume data but do nothing special. Return len to indicate full consumption.
    // In a real implementation, you might pass data to 'm_receiver' if it needs to be inspected further.
    return len;
}

void ParserDefaultSpecial::finish()
{
    dbgTrace(D_WAAP_PARSER) << "ParserDefaultSpecial finish";
}

const std::string &ParserDefaultSpecial::name() const
{
    return m_parserName;
}

bool ParserDefaultSpecial::error() const
{
    return m_error;
}
