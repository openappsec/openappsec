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

#include "ParserDelimiter.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_DELIMITER);

ParserDelimiter::ParserDelimiter(
    IParserStreamReceiver& receiver,
    size_t parser_depth,
    char delim,
    const std::string& delimName
    ) : ParserBase(),
    m_state(s_start),
    m_receiver(receiver),
    m_delim(delim),
    m_delim_name(delimName),
    m_found_delim(false),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_DELIMITER)
        << "parsing delimiter: parser depth="
        << parser_depth;
}

ParserDelimiter::~ParserDelimiter()
{

}

void ParserDelimiter::pushKey()
{
    std::string delim_key = m_delim_name;
    dbgTrace(D_WAAP_PARSER_DELIMITER) << "parsing delimiter: send key='" << delim_key << "'";
    m_receiver.onKey(delim_key.c_str(), delim_key.length());
}

size_t ParserDelimiter::push(const char* data, size_t data_len)
{
    if (data_len == 0)
    {
        if (!m_found_delim)
        {
            m_state = s_error;
            return 0;
        }
        if (m_receiver.onKvDone() != 0) {
            m_state = s_error;
        }
        return 0;
    }
    size_t i = 0, value_start_index = 0;
    while (i < data_len)
    {
        char c = data[i];
        switch (m_state)
        {
        case s_start:
            m_found_delim = false;
            pushKey();
            if (c == m_delim)
            {
                m_state = s_start_with_delimiter;
            }
            else
            {
                m_state = s_value_start;
            }
            break;
        case s_start_with_delimiter:
            m_found_delim = true;
            m_state = s_value_start;
            i++;
            break;
        case s_value_start:
            value_start_index = i;
            m_state = s_value;
            // fall through
        case s_value:
            if (c == m_delim)
            {
                dbgTrace(D_WAAP_PARSER_DELIMITER) << "parsing delimiter: send val='" <<
                    std::string(data + value_start_index, i - value_start_index) << "'";
                m_receiver.onValue(data + value_start_index, i - value_start_index);
                m_state = s_delimiter;
                break;
            }
            else if (i + 1 == data_len)
            {
                dbgTrace(D_WAAP_PARSER_DELIMITER) << "parsing delimiter: send val='" <<
                    std::string(data + value_start_index, i - value_start_index) << "'";
                m_receiver.onValue(data + value_start_index, i - value_start_index + 1);
            }
            i++;
            break;
        case s_delimiter:
            m_found_delim = true;

            dbgTrace(D_WAAP_PARSER_DELIMITER) << "parsing delimiter: send onKvDone";
            if (m_receiver.onKvDone() != 0) {
                m_state = s_error;
                break;
            }

            i++;
            pushKey();
            m_state = s_value_start;
            break;
        case s_error:
            break;
        default:
            break;
        }
        if (m_state == s_error)
        {
            break;
        }
    }

    return 0;
}

void ParserDelimiter::finish()
{
    push(NULL, 0);
}

bool ParserDelimiter::error() const
{
    return m_state == s_error;
}

const std::string& ParserDelimiter::name() const
{
    return m_delim_name;
}
