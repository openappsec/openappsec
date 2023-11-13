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

#include "ParserRaw.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_RAW);

const std::string ParserRaw::m_parserName = "ParserRaw";

ParserRaw::ParserRaw(IParserStreamReceiver &receiver, size_t parser_depth, const std::string &key)
:m_receiver(receiver), m_key(key), m_state(s_start) {
}

ParserRaw::~ParserRaw() {
}

size_t ParserRaw::push(const char *buf, size_t len) {
    dbgTrace(D_WAAP_PARSER_RAW) << "ParserRaw::push(): (len=" << (unsigned long int)len << ")";

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_RAW) << "ParserRaw::push(): end of data signal! m_state=" << m_state;

        // flush unescaped data collected (if any)
        if (m_state != s_start) { // only emit if at least something was pushed
            if (m_receiver.onKvDone() != 0) {
                m_state = s_error;
            }
        }

        return 0;
    }

    switch (m_state) {
    case s_start:
        dbgTrace(D_WAAP_PARSER_RAW) << "ParserRaw::push(): s_start";
        if (m_receiver.onKey(m_key.data(), m_key.size()) != 0) {
            m_state = s_error;
            return 0;
        }
        m_state = s_forward;
        // fallthrough //
        CP_FALL_THROUGH;
    case s_forward:
        dbgTrace(D_WAAP_PARSER_RAW) << "ParserRaw::push(): s_forward";

        if (m_receiver.onValue(buf, len) != 0) {
            m_state = s_error;
        }
        break;
    case s_error:
        dbgTrace(D_WAAP_PARSER_RAW) << "ParserRaw::push(): s_error";
        return 0;
    }

    return len;
}

void ParserRaw::finish() {
    push(NULL, 0);
}

const std::string &
ParserRaw::name() const {
    return m_parserName;
}

bool ParserRaw::error() const {
    return m_state == s_error;
}
