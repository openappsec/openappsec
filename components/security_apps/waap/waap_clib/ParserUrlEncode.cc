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

#include "ParserUrlEncode.h"
#include "Waf2Util.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_URLENCODE);
USE_DEBUG_FLAG(D_WAAP);

const std::string ParserUrlEncode::m_parserName = "ParserUrlEncode";

ParserUrlEncode::ParserUrlEncode(
    IParserStreamReceiver &receiver, size_t parser_depth, char separatorChar, bool should_decode_per
) :
    m_receiver(receiver),
    m_state(s_start),
    m_escapedLen(0),
    m_separatorChar(separatorChar),
    m_escapedCharCandidate(0),
    should_decode_percent(should_decode_per),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP)
        << "should_decode_percent="
        << should_decode_per
        << "parser_depth="
        << parser_depth;

    // TODO:: is there a need for this?
    memset(m_escaped, 0, sizeof(m_escaped));
}

ParserUrlEncode::~ParserUrlEncode()
{}

size_t
ParserUrlEncode::push(const char *buf, size_t len)
{
    size_t i = 0;
    size_t mark = 0;
    char c;
    int is_last = 0;

    dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): starting (len=" << len << ")";

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): end of data signal! m_state=" << m_state;
        // flush unescaped data collected (if any)
        if (m_escapedLen > 0) {
            if (m_state == s_key_start) {
                if (m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
            } else if (m_state == s_value_start) {
                if (m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
            }
            m_escapedLen = 0;
        }

        if (m_receiver.onKvDone() != 0) {
            m_state = s_error;
            return i;
        }

        return 0;
    }

    while (i < len) {
        c = buf[i];
        is_last = (i == (len - 1));

        // Checking valid char urlencode
        if (c < 32) {
            dbgDebug(D_WAAP_PARSER_URLENCODE) << "invalid URL encoding character: " << c;
            m_state = s_error;
            return i;
        }

        dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): state=" << m_state << "; ch='" << c << "'";

        switch (m_state) {
        case s_start: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_start";
            //m_state = s_key_start;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_key_start: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_key_start";
            mark = i;
            m_state = s_key;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_key: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_key";

            // skip leading spaces in the key
            if (isspace(c)) {
                m_state = s_key_start; // skip the space character without including it in the output
                break;
            }

            if (c == '%' && should_decode_percent) {
                if (i - mark > 0) {
                    if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                        m_state = s_error;
                        return i;
                    }
                }
                m_state = s_key_escaped1;
                break;
                } else if (c == '+') {
                // convert plus character to space
                if (i - mark > 0) {
                    if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    mark = i;
                }
                m_escaped[m_escapedLen] = ' ';
                m_escapedLen++;
                if (m_escapedLen >= MAX_URLENCODE_ESCAPED_SIZE) {
                    if (m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                }
                m_state = s_key_start;
                break;
                } else {
                // flush unescaped data collected (if any)
                if (m_escapedLen > 0) {
                    if (m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                    mark = i;
                }
            }
            if (c == m_separatorChar) {
                // this happens when there is a key without value. Example: ?p&a=b&k&%61&blah
                // in this case we emit the key, but not the value, and send onKvDone to cause
                // the receiver to process the pair: key will be provided with no value.
                if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                    m_state = s_error;
                    return i;
                }
                if (m_receiver.onKvDone() != 0) {
                    m_state = s_error;
                    return i;
                }
                m_state = s_key_start;
                break;
            }
            if (c == '=') {
                if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_state = s_value_start;
                break;
            }
            if (is_last) {
                if (m_receiver.onKey(buf + mark, (i - mark) + 1) != 0) {
                    m_state = s_error;
                    return i;
                }
            }
            break;
        }
        case s_key_escaped1: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_key_escaped1";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) { // character right after the '%' is not a valid hex char.
                // dump escaped chars
                if (m_escapedLen > 0 && m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;
                // return the '%' character back to the output.
                if (m_receiver.onKey("%", 1) != 0) {
                    return i;
                }

                // If the character is '%' - stay in the same state (correctly treat '%%%%hhh' sequences
                if (c != '%') {
                    // pass the non-hex character back to the output too.
                    if (m_receiver.onKey(&c, 1) != 0) {
                        return i;
                    }

                    // otherwise (the character is not '%'), switch back to the s_key state
                    m_state = s_key_start;
                }
                break;
            }

            m_escapedCharCandidate = c;
            m_escaped[m_escapedLen] = v << 4;
            m_state = s_key_escaped2;
            break;
        }
        case s_key_escaped2: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_key_escaped2";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) {
                // This situation (2nd character is not valid hex) is not treated right now.
                // In this case, v will be equal to 0 and output character will be invalid one.

                //dump escaped chars
                if (m_escapedLen >0 && m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;

                // return the '%' character back to the output.
                if (m_receiver.onKey("%", 1) != 0) {
                    return i;
                }
                // add the character that was thought to be escaped value
                if (m_receiver.onKey(&m_escapedCharCandidate, 1)) {
                    return i;
                }

                // re parse the character as a key (i is incremented back to current value)
                i--;
                m_state = s_key_start;
                break;
            }
            m_escapedCharCandidate = 0;
            m_escaped[m_escapedLen] |= v;
            m_escapedLen++;
            if (m_escapedLen >= MAX_URLENCODE_ESCAPED_SIZE) {
                if (m_receiver.onKey(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;
            }
            m_state = s_key_start;
            break;
        }
        case s_value_start: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_value_start";
            mark = i;
            m_state = s_value;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_value: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_value";
            if (c == '%' && should_decode_percent) {
                if (i - mark > 0) {
                    if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                        m_state = s_error;
                        return i;
                    }
                }
                m_state = s_value_escaped1;
                break;
                } else if (c == '+') {
                // convert plus character to space
                if (i - mark > 0) {
                    if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                        m_state = s_error;
                        return i;
                    }
                }
                m_escaped[m_escapedLen] = ' ';
                m_escapedLen++;
                if (m_escapedLen >= MAX_URLENCODE_ESCAPED_SIZE) {
                    if (m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                }
                m_state = s_value_start;
                break;
                } else {
                // flush unescaped data collected (if any)
                if (m_escapedLen > 0) {
                    if (m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                        m_state = s_error;
                        return i;
                    }
                    m_escapedLen = 0;
                    mark = i;
                }
            }
            if (c == m_separatorChar) {
                if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                    dbgWarning(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push() s_value : failed on value";
                    m_state = s_error;
                    return i;
                }
                if (m_receiver.onKvDone() != 0) {
                    dbgWarning(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push() : s_value :  failed on KV";
                    m_state = s_error;
                    return i;
                }
                m_state = s_key_start;
                break;
            }
            if (is_last) {
                if (m_receiver.onValue(buf + mark, (i - mark) + 1) != 0) {
                    m_state = s_error;
                    return i;
                }
            }
            break;
        }
        case s_value_escaped1: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_value_escaped1";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) { // character right after the '%' is not a valid hex char.
                // dump escaped chars
                if (m_escapedLen > 0 && m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;
                // return the '%' character back to the output.
                if (m_receiver.onValue("%", 1) != 0) {
                    return i;
                }

                // If the character is '%' - stay in the same state (correctly treat '%%%%hhh' sequences)
                if (c != '%') {
                    // pass the non-hex character back to the output too.
                    if (m_receiver.onValue(&c, 1) != 0) {
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
        case s_value_escaped2: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_value_escaped2";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) {
                // This situation (2nd character is not valid hex) is not treated right now.
                // In this case, v will be equal to 0 and output character will be invalid one.

                //dump escaped chars
                if (m_escapedLen > 0 && m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;

                // return the '%' character back to the output.
                if (m_receiver.onValue("%", 1) != 0) {
                    return i;
                }
                // add the character that was thought to be escaped value
                if (m_receiver.onValue(&m_escapedCharCandidate, 1)) {
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
            if (m_escapedLen >= MAX_URLENCODE_ESCAPED_SIZE) {
                if (m_receiver.onValue(m_escaped, m_escapedLen) != 0) {
                    m_state = s_error;
                    return i;
                }
                m_escapedLen = 0;
            }
            m_state = s_value_start;
            break;
        }
        case s_error: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): s_error";
            return 0;
        }
        default: {
            dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): URL parser unrecoverable error";
            m_state = s_error;
            return 0;
        }
        }// end of switch()
        ++i;
    }

    dbgTrace(D_WAAP_PARSER_URLENCODE) << "ParserUrlEncode::push(): finished: len=" << len;
    return len;
}

void
ParserUrlEncode::finish()
{
    push(NULL, 0);
}

const std::string &
ParserUrlEncode::name() const
{
    return m_parserName;
}

bool
ParserUrlEncode::error() const
{
    return m_state == s_error;
}
