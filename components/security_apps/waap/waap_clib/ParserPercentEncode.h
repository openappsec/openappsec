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

#ifndef __PARSER_PERCENT_ENCODE_H_
#define __PARSER_PERCENT_ENCODE_H_

#include "ParserBase.h"
#include <string.h>

#define MAX_PERCENT_ENCODED_SIZE 255
#define VALID_URL_CODE_START 32

class ParserPercentEncode : public ParserBase {
public:
    ParserPercentEncode(IParserStreamReceiver &receiver, size_t parser_depth);
    virtual ~ParserPercentEncode();
    size_t push(const char *data, size_t data_len);
    void finish();
    virtual const std::string &name() const;
    bool error() const;

    virtual size_t
    depth()
    {
        return 1;
    }

private:
    enum state
    {
        s_start,
        s_value_start,
        s_value,
        s_value_escaped1,
        s_value_escaped2,
        s_end,
        s_error
    };

    IParserStreamReceiver &m_receiver;
    enum state m_state;
    unsigned char m_escapedLen;
    char m_escaped[MAX_PERCENT_ENCODED_SIZE];
    char m_escapedCharCandidate;
    static const std::string m_parserName;
    size_t m_parser_depth;
};

#endif
