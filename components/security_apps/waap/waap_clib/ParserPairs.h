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

#ifndef __PARSER_PAIRS_H__
#define __PARSER_PAIRS_H__

#include "ParserBase.h"
#include <string.h>

#define MAX_PAIRS_ESCAPED_SIZE 16

class ParserPairs : public ParserBase {
public:
    ParserPairs(
        IParserStreamReceiver &receiver,
        size_t parser_depth,
        char separatorChar = '&',
        bool should_decode_per = false,
        bool should_decode_plus_sign = false);
    virtual ~ParserPairs();
    size_t push(const char *data, size_t data_len);
    void finish();
    virtual const std::string &name() const;
    bool error() const;
    virtual size_t depth() { return 1; }

private:
    enum state {
        s_start,
        s_key_start,
        s_key,
        s_key_escaped1,
        s_key_escaped2,
        s_value_start,
        s_value,
        s_value_escaped1,
        s_value_escaped2,
        s_end,
        s_error
    };

    IParserStreamReceiver &m_receiver;
    enum state m_state;
    unsigned char m_escapedLen; // count of characters loaded in m_escaped[] buffer
    char m_escaped[MAX_PAIRS_ESCAPED_SIZE];
    char m_separatorChar;
    char m_escapedCharCandidate;
    bool should_decode_percent;
    bool should_decode_plus;
    static const std::string m_parserName;
    size_t m_parser_depth;
    int m_bracket_counter;
};

#endif // __PARSER_PAIRS_H__
