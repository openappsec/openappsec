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

#include "ParserBinary.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_BINARY);

#define MIN_TEXT_SIZE 10

ParserBinary::ParserBinary(IParserStreamReceiver& receiver, size_t parser_depth) :
    m_parserName("binary"),
    m_receiver(receiver),
    m_state(s_start),
    m_textFromLastBuffer(),
    m_textCharCount(0),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_BINARY)
        << "parser_depth="
        << parser_depth;
}

ParserBinary::~ParserBinary()
{
}

size_t ParserBinary::push(const char* data, size_t data_len)
{
    if (data_len == 0)
    {
        dbgTrace(D_WAAP_PARSER_BINARY) << "ParserBinary::push(): end of stream. m_state=" << m_state <<
            ", m_textCharCount=" << m_textCharCount;

        if (m_state == s_text && m_textCharCount >= MIN_TEXT_SIZE) {
            // Flush text data collected from previous buffer
            flush();
        }

        m_receiver.onKvDone();
        return 0;
    }

    size_t i = 0, textStartIdx = 0;

    while (i < data_len)
    {
        char c = data[i];
        bool is_last = (i + 1 == data_len);

        switch (m_state) {
            case s_start:
                m_receiver.onKey("text", 4);
                m_state = s_binary;
                // fallthrough //
                CP_FALL_THROUGH;
            case s_binary:
                if (!::isprint(c)) {
                    // Skip binary stuff
                    break;
                }

                textStartIdx = i; // remember index of potential text block start
                m_textCharCount = 0; // count consecutive text characters in the input stream

                if (!m_textFromLastBuffer.empty()) {
                    m_textFromLastBuffer.clear();
                }

                m_state = s_text;
                // fallthrough //
                CP_FALL_THROUGH;
            case s_text: {
                if (::isprint(c)) {
                    m_textCharCount++;
                }
                else {
                    dbgTrace(D_WAAP_PARSER_BINARY) << "ParserBinary::push(): switch to binary at i=" << i <<
                        ", textStartIdx=" << textStartIdx << ", m_textCharCount=" << m_textCharCount;
                    // Transition from text to binary
                    // Only output text chunk when it is large enough, ignore small text chunks
                    if (m_textCharCount >= MIN_TEXT_SIZE) {
                        // Flush text data collected from previous buffer
                        flush();
                        // Output text data from current buffer
                        m_receiver.onValue(data+textStartIdx, i-textStartIdx); // do not include current character
                    }

                    m_textCharCount = 0;
                    m_state = s_binary;
                    break;
                }

                // Handle hitting buffer edge while collecting text.
                // Note that current buffer is going to be invalidated so we need to save everything needed to be able
                // to continue on next invocation.
                if (is_last) {
                    dbgTrace(D_WAAP_PARSER_BINARY) << "ParserBinary::push(): last char in buffer. m_textCharCount=" <<
                        m_textCharCount;
                    // If enough data collected so far no need to remember it - flush it to output right away
                    if (m_textCharCount >= MIN_TEXT_SIZE) {
                        // Flush text data collected from previous buffer
                        flush();
                        // Output text data from current buffer
                        m_receiver.onValue(data+textStartIdx, i-textStartIdx + 1); // +1 to include current character
                    }
                    else {
                        // If there's not enough text to decide - store the text data from current buffer for the next
                        // invocation
                        m_textFromLastBuffer.append(data+textStartIdx, i-textStartIdx + 1);
                    }
                }

                break;
            }
            case s_error:
                return 0;
            default:
                break;
        }

        i++;
    }

    return i;
}

void ParserBinary::finish()
{
    push(NULL, 0);
}

const std::string& ParserBinary::name() const
{
    return m_parserName;
}

bool ParserBinary::error() const
{
    return m_state == s_error;
}

void ParserBinary::flush() {
    // Flush text data collected from previous buffer
    if (m_textFromLastBuffer.size() > 0) {
        dbgTrace(D_WAAP_PARSER_BINARY) << "ParserBinary::flush() flushing " << m_textFromLastBuffer.size() <<
            " chars from last buf";
        m_receiver.onValue(m_textFromLastBuffer.data(), m_textFromLastBuffer.size());
        m_textFromLastBuffer.clear();
    }
}
