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

#ifndef __PARSER_DEFAULT_SPECIAL_H__
#define __PARSER_DEFAULT_SPECIAL_H__

#include <string>
#include "ParserBase.h"

class ParserDefaultSpecial : public ParserBase {
public:
    ParserDefaultSpecial(IParserStreamReceiver &receiver, size_t parser_depth);
    virtual ~ParserDefaultSpecial();

    virtual size_t push(const char *buf, size_t len) override;
    virtual void finish() override;
    virtual const std::string &name() const override;
    virtual size_t depth() override { return 1; }
    virtual bool error() const override;

private:
    static const std::string m_parserName;
    IParserStreamReceiver &m_receiver;
    bool m_error;
};

#endif // __PARSER_DEFAULT_SPECIAL_H__
