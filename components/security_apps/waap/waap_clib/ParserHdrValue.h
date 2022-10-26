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

#ifndef __PARSER_HDRVALUE_H__7d37fe50
#define __PARSER_HDRVALUE_H__7d37fe50

#include "ParserBase.h"
#include <string.h>

class ParserHdrValue : public ParserBase{
public:
    ParserHdrValue(IParserStreamReceiver &receiver);
    virtual ~ParserHdrValue();
    size_t push(const char *data, size_t len);
    void finish();
    virtual const std::string &name() const;
    virtual bool error() const;
    virtual size_t depth() { return 1; }
private:
    static const int MAX_ESCAPED_SIZE = 16;

    IParserStreamReceiver &m_receiver;
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
    enum state state;
    char in_key; // turns true when first non-space key character is read
    char in_dbl_quotes; // turns true (1) during double-quoted value parsing
    unsigned char escaped_len; // count of characters loaded in escaped[] buff
    char escaped[MAX_ESCAPED_SIZE];
    char escapedCharCandidate;

    static const std::string m_parserName;
};

#endif // __PARSER_HDRVALUE_H__7d37fe50
