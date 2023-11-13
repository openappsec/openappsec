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

#include "ParserConfluence.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_CONFLUENCE);

ParserConfluence::ParserConfluence(IParserStreamReceiver& receiver, size_t parser_depth) :
    m_parserName("confluence"),
    m_state(s_start),
    m_receiver(receiver),
    m_name(),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_CONFLUENCE)
        << "parser_depth="
        << parser_depth;

}

ParserConfluence::~ParserConfluence()
{
}

size_t ParserConfluence::push(const char* data, size_t data_len)
{
    if (data_len == 0)
    {
        if (m_state != s_end)
        {
            m_state = s_error;
            return 0;
        }
    }
    size_t i = 0, name_index = 0, attribute_index = 0;
    while (i < data_len)
    {
        char c = data[i];
        bool is_last = (i + 1 == data_len);
        dbgTrace(D_WAAP_PARSER_CONFLUENCE) << "parsing confluence: index: " << i << " char: " << c << " state: " <<
            m_state;
        switch (m_state)
        {
        case s_start:
            if (c != '{')
            {
                m_state = s_error;
                break;
            }
            i++;
            m_state = s_start_name;
            break;
        case s_start_name:
            m_name = "";
            name_index = i;
            m_state = s_name;
            break;
        case s_name:
            if (c == ':')
            {
                m_name += std::string(data + name_index, i - name_index);
                m_name += ".";
                m_state = s_start_attributes;
            }
            else if (c == '"')
            {
                m_state = s_error;
                break;
            }
            else if (is_last)
            {
                m_name += std::string(data + name_index, i - name_index + 1);
                name_index = 0;
            }
            i++;
            break;
        case s_start_attributes:
            attribute_index = i;
            m_receiver.onKey(m_name.c_str(), m_name.length());
            m_state = s_attribute_name;
            break;
        case s_attribute_name:
            if (c == '=')
            {
                if (i > attribute_index)
                {
                    m_receiver.onKey(data + attribute_index, i - attribute_index);
                }
                attribute_index = is_last ? 0 : i + 1;
                m_state = s_attribute_value;
            }
            else if (c == '|')
            {
                if (i > attribute_index)
                {
                    m_receiver.onKey(data + attribute_index, i - attribute_index);
                }
                m_receiver.onKvDone();
                m_state = s_start_attributes;
            }
            else if (c == '}')
            {
                if (i > attribute_index)
                {
                    m_receiver.onKey(data + attribute_index, i - attribute_index);
                }
                m_receiver.onKvDone();
                m_state = s_end;
            }
            else if (is_last)
            {
                m_receiver.onKey(data + attribute_index, i - attribute_index + 1);
                attribute_index = 0;
            }
            i++;
            break;
        case s_attribute_value:
            if (c == '|')
            {
                if (i > attribute_index)
                {
                    m_receiver.onValue(data + attribute_index, i - attribute_index);
                }
                m_receiver.onKvDone();
                m_state = s_start_attributes;
            }
            else if (c == '}')
            {
                if (i > attribute_index)
                {
                    m_receiver.onValue(data + attribute_index, i - attribute_index);
                }
                m_receiver.onKvDone();
                m_state = s_end;
                break;
            }
            else if (is_last)
            {
                m_receiver.onValue(data + attribute_index, i - attribute_index + 1);
                attribute_index = 0;
            }
            i++;
            break;
        case s_end:
            if (!is_last)
            {
                m_state = s_error;
            }
            i++;
            break;
        case s_error:
            return i;
            break;
        default:
            break;
        }
    }
    return 0;
}

void ParserConfluence::finish()
{
    push(NULL, 0);
}

const std::string& ParserConfluence::name() const
{
    return m_parserName;
}

bool ParserConfluence::error() const
{
    return m_state == s_error;
}
