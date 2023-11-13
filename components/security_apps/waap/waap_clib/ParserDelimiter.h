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

#ifndef __PARSER_DELIMIETER_BASE_H__
#define __PARSER_DELIMIETER_BASE_H__

#include "ParserBase.h"

class ParserDelimiter : public ParserBase
{
public:
    ParserDelimiter(IParserStreamReceiver& receiver, size_t parser_depth, char delim, const std::string& delimName);
    virtual ~ParserDelimiter();

    virtual size_t push(const char* data, size_t data_len);
    virtual void finish();
    virtual bool error() const;
    virtual const std::string& name() const;
    virtual size_t depth() { return 1; }
private:
    enum state {
        s_start,
        s_start_with_delimiter,
        s_value_start,
        s_delimiter,
        s_value,
        s_error
    };

    void pushKey();

    state m_state;
    IParserStreamReceiver& m_receiver;
    std::string m_key;
    char m_delim;
    std::string m_delim_name;
    bool m_found_delim;
    size_t m_parser_depth;
};


#endif
