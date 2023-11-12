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

#ifndef __CONTENT_TYPE_PARSER_H__aa67ad9a
#define __CONTENT_TYPE_PARSER_H__aa67ad9a

#include "ParserBase.h"
#include "ParserHdrValue.h"
#include "debug.h"
#include <string>

class ContentTypeParser : public ParserBase, private IParserReceiver {
    enum CtParserState {
        CTP_STATE_CONTENT_TYPE,
        CTP_STATE_CONTENT_TYPE_PARAMS
    } ctParserState;
private:
    virtual int onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth);

public:
    ContentTypeParser();
    virtual size_t push(const char *data, size_t data_len);
    virtual void finish();
    virtual const std::string &name() const;
    bool error() const;
    virtual size_t depth() { return 1; }

    // After call to execute(), parsing results can be picked up from these variables
    std::string contentTypeDetected;
    std::string boundaryFound;
private:
    BufferedReceiver m_rcvr;
    ParserHdrValue m_hvp;
    bool m_error;

    static const std::string m_parserName;
};

#endif // __CONTENT_TYPE_PARSER__aa67ad9a
