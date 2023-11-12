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

#ifndef __PARSER_BINARY_H__
#define __PARSER_BINARY_H__

#include "ParserBase.h"

class ParserBinary : public ParserBase
{
public:
    ParserBinary(IParserStreamReceiver& receiver, size_t parser_depth);
    virtual ~ParserBinary();
    virtual size_t push(const char* data, size_t data_len);
    virtual void finish();
    virtual const std::string& name() const;
    virtual bool error() const;
    virtual size_t depth() { return 1; }
private:
    enum state {
        s_start,
        s_binary,
        s_text,
        s_error
    };

    const std::string m_parserName;
    IParserStreamReceiver& m_receiver;
    state m_state;
    std::string m_textFromLastBuffer;
    size_t m_textCharCount;
    size_t m_parser_depth;
    void flush();
};

#endif // __PARSER_BINARY_H__
