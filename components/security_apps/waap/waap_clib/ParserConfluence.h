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

#ifndef __PARSER_CONFLUENCE_H__
#define __PARSER_CONFLUENCE_H__

#include "ParserBase.h"

class ParserConfluence : public ParserBase
{
public:
    ParserConfluence(IParserStreamReceiver& receiver, size_t parser_depth);
    virtual ~ParserConfluence();

    virtual size_t push(const char* data, size_t data_len);
    virtual void finish();
    virtual const std::string& name() const;
    virtual bool error() const;
    virtual size_t depth() { return 1; }
private:
    enum state {
        s_start,
        s_start_name,
        s_name,
        s_start_attributes,
        s_attribute_name,
        s_attribute_value,
        s_end,
        s_error
    };

    const std::string m_parserName;
    state m_state;
    IParserStreamReceiver& m_receiver;
    std::string m_name;
    size_t m_parser_depth;
};

#endif
