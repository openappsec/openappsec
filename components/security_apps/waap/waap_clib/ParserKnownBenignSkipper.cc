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

#include "ParserKnownBenignSkipper.h"
#include "Waf2Util.h"
#include "debug.h"
#include <string.h>
USE_DEBUG_FLAG(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER);
USE_DEBUG_FLAG(D_WAAP);

const std::string ParserKnownBenignSkipper::m_parserName = "ParserKnownBenignSkipper";
const char* DATA_SENSOR_TAIL = "\"}";

ParserKnownBenignSkipper::ParserKnownBenignSkipper(
    IParserStreamReceiver &receiver,
    size_t parser_depth,
    Waap::Util::KnownSourceType source_type
) :
    m_receiver(receiver),
    m_state(s_start),
    m_parser_depth(parser_depth),
    m_source_type(source_type)
{}

ParserKnownBenignSkipper::~ParserKnownBenignSkipper()
{}

size_t
ParserKnownBenignSkipper::push(const char *buf, size_t len)
{
    dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
        << "buf='"
        << std::string(buf, std::min((size_t)200, len))
        << (len > 200 ? "..." : "")
        << "' len="
        << len
        << " depth="
        << depth();

    const char *c;

    if (m_state == s_error) {
        return 0;
    }
    if (len == 0)
    {
        dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
            << "ParserKnownBenignSkipper::push(): end of stream. m_state="
            << m_state;

        if (m_state == s_end) {
            m_receiver.onKvDone();
        } else {
            m_state = s_error;
        }
        return 0;
    }

    size_t tail_lookup_offset = 0;

    switch (m_state) {
            case s_start:
                m_state = s_body;
                CP_FALL_THROUGH;
            case s_body:
                {
                    if (m_source_type == Waap::Util::SOURCE_TYPE_SENSOR_DATA) {
                        tail_lookup_offset =
                            (len > MAX_DATA_SENSOR_TAIL_LOOKUP) ? len - MAX_DATA_SENSOR_TAIL_LOOKUP : 0;
                        c = strstr(buf + tail_lookup_offset, DATA_SENSOR_TAIL);
                        if (c) {
                            dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
                                << "ParserKnownBenignSkipper::push(): found end of sensor data";
                            m_state = s_end;
                            CP_FALL_THROUGH;
                        } else {
                            break;
                        }
                    } else {
                        dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
                            << "ParserKnownBenignSkipper::push(): unknown source type";
                        m_state = s_error;
                        break;
                    }
                }
            case s_end:
                dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER) << "state = end";
                if (m_receiver.onKey("SENSOR_DATA", 11) != 0) {
                    dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER) << "state moving to error onKey";
                    m_state = s_error;
                    return 0;
                }
                if (m_receiver.onValue("", 0) != 0) {
                    dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER) << "state moving to error onValue";
                    m_state = s_error;
                    return 0;
                }
                break;
            case s_error:
                dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER) << "state = error";
                break;
            default:
                dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
                    << "ParserKnownBenignSkipper::push(): unknown state: "
                    << m_state;
                m_state = s_error;
                return 0;
    }
    dbgTrace(D_WAAP_PARSER_KNOWN_SOURCE_SKIPPER)
        << "ParserKnownBenignSkipper::push(): final state: "
        << m_state;
    return len;
}


void ParserKnownBenignSkipper::finish()
{
    push(NULL, 0);
}

const std::string& ParserKnownBenignSkipper::name() const
{
    return m_parserName;
}

bool ParserKnownBenignSkipper::error() const
{
    return m_state == s_error;
}
