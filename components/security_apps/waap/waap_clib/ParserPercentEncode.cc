// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "ParserPercentEncode.h"
#include "Waf2Util.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_PERCENT);

const std::string ParserPercentEncode::m_parserName = "ParserPercentEncode";

ParserPercentEncode::ParserPercentEncode(IParserStreamReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_state(s_start),
    m_escapedLen(0),
    m_escapedCharCandidate(0),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_PERCENT)
        << "parser_depth="
        << parser_depth;

    memset(m_escaped, 0, sizeof(m_escaped));
}

ParserPercentEncode::~ParserPercentEncode()
{}

size_t
ParserPercentEncode::push(const char *buf, size_t len)
{
    size_t i = 0;
    size_t pointer_in_buffer = 0;
    char c;
    int is_last = 0;

    dbgTrace(D_WAAP_PARSER_PERCENT) << "ParserPercentEncode::push(): starting (len=" << len << ")";

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_PERCENT) << "ParserPercentEncode::push(): end of data signal! m_state=" << m_state;
        // flush unescaped data collected (if any)
        if (m_escapedLen > 0)
        {
            if (m_state == s_value_start)
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                    << m_escaped
                    << "<<< and m_escapedLen = "
                    << m_escapedLen;
                if (m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
            }
            m_escapedLen = 0;
        }

        if (m_receiver.onKvDone() != 0)
        {
            m_state = s_error;
            return i;
        }

        return 0;
    }

    while (i < len)
    {
        c = buf[i];
        is_last = (i == (len - 1));

        // Checking valid char urlencode
        if (c < VALID_URL_CODE_START)
        {
            dbgDebug(D_WAAP_PARSER_PERCENT)
                << "invalid URL encoding character: "
                << c;
            m_state = s_error;
            return i;
        }

        dbgTrace(D_WAAP_PARSER_PERCENT)
            << "ParserPercentEncode::push(): state="
            << m_state
            << "; ch='"
            << c
            << "'";

        switch (m_state)
        {
            case s_start:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_start";
                // fallthrough //
                CP_FALL_THROUGH;
            }
            case s_value_start:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_value_start";
                pointer_in_buffer = i;
                m_state = s_value;
                // fallthrough //
                CP_FALL_THROUGH;
            }
            case s_value:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_value";
                if (c == '%')
                {
                    if (i - pointer_in_buffer > 0)
                    {
                        dbgTrace(D_WAAP_PARSER_PERCENT)
                            << "ParserPercentEncode::push(): call onValue with buffer = >>>"
                            << (buf + pointer_in_buffer)
                            << "<<< of size "
                            << i - pointer_in_buffer;
                        if (m_receiver.onValue(buf + pointer_in_buffer, i - pointer_in_buffer) != 0)
                        {
                            m_state = s_error;
                            return i;
                        }
                    }
                    m_state = s_value_escaped1;
                    break;
                }
                else
                {
                    // flush unescaped data collected (if any)
                    if (m_escapedLen > 0)
                    {
                        dbgTrace(D_WAAP_PARSER_PERCENT)
                            << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                            << m_escaped
                            << "<<< and m_escapedLen = "
                            << m_escapedLen;
                        if (m_receiver.onValue(m_escaped, m_escapedLen) != 0)
                        {
                            m_state = s_error;
                            return i;
                        }
                        m_escapedLen = 0;
                        pointer_in_buffer = i;
                    }
                }
                if (is_last)
                {
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                        << (buf + pointer_in_buffer)
                        << "<<< of size "
                        << (i - pointer_in_buffer) + 1;
                    if (m_receiver.onValue(buf + pointer_in_buffer, (i - pointer_in_buffer) + 1) != 0)
                    {
                        m_state = s_error;
                        return i;
                    }
                }
                break;
            }
            case s_value_escaped1:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_value_escaped1";
                bool valid;
                unsigned char v = from_hex(c, valid);
                // character right after the '%' is not a valid hex char.
                if (!valid)
                {
                    // dump escaped chars
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                        << m_escaped
                        << "<<< and m_escapedLen = "
                        << m_escapedLen;
                    if (m_escapedLen > 0
                        && m_receiver.onValue(m_escaped, m_escapedLen) != 0)
                    {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                    // return the '%' character back to the output.
                    dbgTrace(D_WAAP_PARSER_PERCENT) << "ParserPercentEncode::push(): call onValue with \"%\" = >>>"
                                                    << "%"
                                                    << "<<<";
                    if (m_receiver.onValue("%", 1) != 0)
                    {
                        return i;
                    }

                    // If the character is '%' - stay in the same state (correctly treat '%%%%hhh' sequences)
                    if (c != '%')
                    {
                        // pass the non-hex character back to the output too.
                        dbgTrace(D_WAAP_PARSER_PERCENT)
                            << "ParserPercentEncode::push(): call onValue with current char = >>>"
                            << c
                            << "<<<";
                        if (m_receiver.onValue(&c, 1) != 0)
                        {
                            return i;
                        }

                        // otherwise (the character is not '%'), switch back to the s_value state
                        m_state = s_value_start;
                    }
                    break;
                }
                m_escapedCharCandidate = c;
                m_escaped[m_escapedLen] = v << 4;
                m_state = s_value_escaped2;
                break;
            }
            case s_value_escaped2:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_value_escaped2";
                bool valid;
                unsigned char v = from_hex(c, valid);
                if (!valid)
                {
                    // This situation (2nd character is not valid hex) is not treated right now.
                    // In this case, v will be equal to 0 and output character will be invalid one.

                    // dump escaped chars
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                        << m_escaped
                        << "<<< and m_escapedLen = "
                        << m_escapedLen;
                    if (m_escapedLen > 0
                        && m_receiver.onValue(m_escaped, m_escapedLen) != 0)
                    {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;

                    // return the '%' character back to the output.
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with \"%\" >>>"
                        << "%"
                        << "<<<";
                    if (m_receiver.onValue("%", 1) != 0)
                    {
                        return i;
                    }
                    // add the character that was thought to be escaped value
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with m_escapedCharCandicate = >>>"
                        << m_escapedCharCandidate
                        << "<<<";
                    if (m_receiver.onValue(&m_escapedCharCandidate, 1))
                    {
                        return i;
                    }

                    // re parse the character as a key (i is incremented back to current value)
                    i--;
                    m_state = s_value_start;
                    break;
                }
                m_escapedCharCandidate = 0;
                m_escaped[m_escapedLen] |= v;
                m_escapedLen++;
                if (m_escapedLen >= MAX_PERCENT_ENCODED_SIZE)
                {
                    dbgTrace(D_WAAP_PARSER_PERCENT)
                        << "ParserPercentEncode::push(): call onValue with m_escaped = >>>"
                        << m_escaped
                        << "<<< and m_escapedLen = "
                        << m_escapedLen;
                    if (m_receiver.onValue(m_escaped, m_escapedLen) != 0)
                    {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                }
                m_state = s_value_start;
                break;
            }
            case s_error:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): s_error";
                return 0;
            }
            default:
            {
                dbgTrace(D_WAAP_PARSER_PERCENT)
                    << "ParserPercentEncode::push(): URL parser unrecoverable error";
                m_state = s_error;
                return 0;
            }
        }
        ++i;
    }

    dbgTrace(D_WAAP_PARSER_PERCENT)
        << "ParserPercentEncode::push(): finished: len="
        << len;
    return len;
}

void
ParserPercentEncode::finish()
{
    push(NULL, 0);
}

const std::string &
ParserPercentEncode::name() const
{
    return m_parserName;
}

bool
ParserPercentEncode::error() const
{
    return m_state == s_error;
}
