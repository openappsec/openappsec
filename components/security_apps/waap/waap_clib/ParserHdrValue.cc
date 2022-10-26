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

#include "ParserHdrValue.h"
#include "Waf2Util.h"
#include "debug.h"
#include <stdio.h>
#include <string.h>

USE_DEBUG_FLAG(D_WAAP_PARSER_HDRVALUE);

const std::string ParserHdrValue::m_parserName = "hdrValue";

enum state {
    s_start,
    s_key_start,
    s_key_restart,
    s_key,
    s_key_escaped1,
    s_key_escaped2,
    s_value_start,
    s_value_restart,
    s_value,
    s_value_escaped1,
    s_value_escaped2,
    s_value_finishing_after_dblquotes,
    s_end
};

ParserHdrValue::ParserHdrValue(IParserStreamReceiver& receiver)
    :m_receiver(receiver), in_key(0), in_dbl_quotes(0), escaped_len(0), escapedCharCandidate(0) {
    // TODO:: maybe remove?
    memset(escaped, 0, sizeof(escaped));
    state = s_start;
}

ParserHdrValue::~ParserHdrValue() {
}

size_t ParserHdrValue::push(const char* buf, size_t len) {
    size_t i = 0;
    size_t mark = 0;
    char c;
    int is_last = 0;

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): end of data signal! state=" << state;
        // flush unescaped data collected (if any)
        if (escaped_len > 0) {
            if (state == s_key_restart) {
                if (m_receiver.onKey(escaped, escaped_len) != 0) {
                    return i;
                }
            }
            else if (state == s_value_restart) {
                if (m_receiver.onValue(escaped, escaped_len) != 0) {
                    return i;
                }
            }
            if (m_receiver.onKvDone() != 0) {
                return i;
            }
            escaped_len = 0;
        }

        if (m_receiver.onKvDone() != 0) {
            return i;
        }

        return 0;
    }

    while (i < len) {
        c = buf[i];
        is_last = (i == (len - 1));

        switch (state) {
        case s_start: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_start";
            //state = s_key_start;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_key_start: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key_start";
            in_key = 0; // we are not parsing the key
            //state = s_key_restart;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_key_restart: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key_restart";
            mark = i;
            state = s_key;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_key: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key; c='" << c << "'; in_key=" << in_key;

            // skip leading spaces in the key
            if (isspace(c) && !in_key) {
                state = s_key_restart; // skip the space character without including it in the output
                break;
            }

            // Note that first non-space character is read
            in_key = 1;

            if (c == '%') {
                if (i - mark > 0) {
                    if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                        return i;
                    }
                }
                state = s_key_escaped1;
                break;
            }
#if 0 // '+' encoding is not done in header values (AFAIK)
            else if (c == '+') {
                // convert plus character to space
                if (i - mark > 0) {
                    EMIT_DATA_CB(key, i, buf + mark, i - mark);
                    mark = i;
                }
                escaped[escaped_len] = ' ';
                escaped_len++;
                if (escaped_len >= MAX_ESCAPED_SIZE) {
                    EMIT_DATA_CB(value, i, escaped, escaped_len);
                    escaped_len = 0;
                }
                state = s_key_restart;
                break;
            }
#endif
            else {
                // flush unescaped data collected (if any)
                if (escaped_len > 0) {
                    if (m_receiver.onKey(escaped, escaped_len) != 0) {
                        return i;
                    }
                    escaped_len = 0;
                    mark = i;
                }
            }
            if (c == ';') {
                // name finished without value
                if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                    return i;
                }
                if (m_receiver.onKvDone() != 0) {
                    return i;
                }
                state = s_key_start;
                break;
            }
            else if (c == '=') {
                if (m_receiver.onKey(buf + mark, i - mark) != 0) {
                    return i;
                }
                state = s_value_start;
                break;
            }
            if (is_last) {
                if (m_receiver.onKey(buf + mark, (i - mark) + 1) != 0) {
                    return i;
                }
            }
            break;
        }
        case s_key_escaped1: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key_escaped1";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) { // character right after the '%' is not a valid hex char.
                // return the '%' character back to the output.
                if (escaped_len > 0) {
                    if (m_receiver.onKey(escaped, escaped_len) != 0) {
                        return i;
                    }
                    escaped_len = 0;
                }
                if (m_receiver.onKey("%", 1) != 0) {
                    return i;
                }

                // If the character is '%' - stay in the same state (correctly treat '%%%%hhh' sequences
                if (c != '%') {
                    // pass the non-hex character back to the output too.
                    if (m_receiver.onKey(&c, 1) != 0) {
                        return i;
                    }

                    // otherwise (the character is not '%s'), switch back to the s_key state
                    state = s_key;
                }
                break;
            }
            escapedCharCandidate = c;
            escaped[escaped_len] = v << 4;
            state = s_key_escaped2;
            break;
        }
        case s_key_escaped2: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key_escaped2";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) {
                // add converted escaped chars
                if (escaped_len > 0 && m_receiver.onKey(escaped, escaped_len)) {
                    return i;
                }

                // return % to output
                if (m_receiver.onKey("%", 1) != 0) {
                    return i;
                }

                // add the character that was thought to be escaped value
                if (m_receiver.onKey(&escapedCharCandidate, 1)) {
                    return i;
                }

                // re parse the character as a key (i is incremented back to current value)
                i--;
                escaped_len = 0;
                state = s_key_restart;
                break;
            }
            escapedCharCandidate = 0;
            escaped[escaped_len] |= v;
            escaped_len++;
            if (escaped_len >= MAX_ESCAPED_SIZE) {
                if (m_receiver.onKey(escaped, escaped_len) != 0) {
                    return i;
                }
                escaped_len = 0;
            }
            state = s_key_restart;
            break;
        }
        case s_value_start: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_value_start";
            mark = i;
            state = s_value;
            in_dbl_quotes = 0; // we are not parsing the

            // detect first double-quotes
            if (c == '"' && !in_dbl_quotes) {
                in_dbl_quotes = 1;
                state = s_value_restart;
                break; // skip the leading " character
            }

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_value_restart: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_value_restart";
            mark = i;
            state = s_value;

            // fallthrough //
            CP_FALL_THROUGH;
        }
        case s_value: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_value; c='" << c << "', in_dbl_quotes=" <<
                in_dbl_quotes;
            if (c == '%') {
                if (i - mark > 0) {
                    if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                        return i;
                    }
                }
                state = s_value_escaped1;
                break;
            }
            else if (c == '+') {
                // convert plus character to space
                if (i - mark > 0) {
                    if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                        return i;
                    }
                }
                escaped[escaped_len] = ' ';
                escaped_len++;
                if (escaped_len >= MAX_ESCAPED_SIZE) {
                    if (m_receiver.onValue(escaped, escaped_len) != 0) {
                        return i;
                    }
                    escaped_len = 0;
                }
                state = s_value_restart;
                break;
            }
            else {
                // flush unescaped data collected (if any)
                if (escaped_len > 0) {
                    if (m_receiver.onValue(escaped, escaped_len) != 0) {
                        return i;
                    }
                    escaped_len = 0;
                    mark = i;
                }
            }

            // detect end of dbl-quotes
            if (c == '"' && in_dbl_quotes) {
                if (i - mark > 0) {
                    if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                        return i;
                    }
                }
                if (m_receiver.onKvDone() != 0) {
                    return i;
                }
                state = s_value_finishing_after_dblquotes;
                break;
            }

            if (c == ';') {
                if (m_receiver.onValue(buf + mark, i - mark) != 0) {
                    return i;
                }
                if (m_receiver.onKvDone() != 0) {
                    return i;
                }
                state = s_key_start;
                break;
            }
            if (is_last) {
                if (m_receiver.onValue(buf + mark, (i - mark) + 1) != 0) {
                    return i;
                }
            }
            break;
        }
        case s_value_escaped1: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_value_escaped1";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) { // character right after the '%' is not a valid hex char.
                // return the '%' character back to the output.
                if (m_receiver.onValue("%", 1) != 0) {
                    return i;
                }

                // If the character is '%' - stay in the same state (correctly treat '%%%%hhh' sequences
                if (c != '%') {
                    // pass the non-hex character back to the output too.
                    if (m_receiver.onValue(&c, 1) != 0) {
                        return i;
                    }

                    // otherwise (the character is not '%'), switch back to the s_value state
                    state = s_value_restart;
                }
                break;
            }
            escapedCharCandidate = c;
            escaped[escaped_len] = v << 4;
            state = s_value_escaped2;
            break;
        }
        case s_value_escaped2: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_key_escaped2";
            bool valid;
            unsigned char v = from_hex(c, valid);
            if (!valid) {
                // add converted escaped chars
                if (escaped_len > 0 && m_receiver.onValue(escaped, escaped_len) != 0) {
                    return i;
                }

                // return % to output
                if (m_receiver.onValue("%", 1) != 0) {
                    return i;
                }

                // add the character that was thought to be escaped value
                if (m_receiver.onValue(&escapedCharCandidate, 1)) {
                    return i;
                }

                // re parse the character as a key (i is incremented back to current value)
                i--;
                escaped_len = 0;
                state = s_value_restart;
                break;
            }
            escapedCharCandidate = 0;
            escaped[escaped_len] |= v;
            escaped_len++;
            if (escaped_len >= MAX_ESCAPED_SIZE) {
                if (m_receiver.onValue(escaped, escaped_len) != 0) {
                    return i;
                }
                escaped_len = 0;
            }
            state = s_value_restart;
            break;
        }
        case s_value_finishing_after_dblquotes: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): s_value_finishing_after_dblquotes; c='" <<
                c << "'";
            if (c == ';') {
                state = s_key_start;
                break;
            }
            break;
        }
        default: {
            dbgTrace(D_WAAP_PARSER_HDRVALUE) << "ParserHdrValue::push(): hdrvalue parser unrecoverable error";
            return 0;
        }
        }// end switch()
        ++i;
    }

    return len;
}

void ParserHdrValue::finish() {
    push(NULL, 0);
}

const std::string &
ParserHdrValue::name() const {
    return m_parserName;
}

bool ParserHdrValue::error() const {
    //return m_state == s_error;
    return false; // TODO:: add error handling
}
