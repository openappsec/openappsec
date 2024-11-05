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

#ifndef __PARSER_PDF_H__
#define __PARSER_PDF_H__

#include "ParserBase.h"
#include <string.h>

#define MAX_PDF_HEADER_LOOKUP 64
#define MAX_PDF_TAIL_LOOKUP 20

class ParserPDF : public ParserBase {
public:
    ParserPDF(IParserStreamReceiver &receiver, size_t parser_depth);
    virtual ~ParserPDF();
    virtual size_t push(const char *buf, size_t len);
    virtual void finish();
    virtual const std::string &name() const;
    virtual bool error() const;
    virtual size_t depth() { return 1; }

private:
    enum state {
        s_start,
        s_body,
        s_end,
        s_error
    };

    IParserStreamReceiver &m_receiver;
    enum state m_state;
    static const std::string m_parserName;
    size_t m_parser_depth;
};

#endif // __PARSER_PDF_H__
