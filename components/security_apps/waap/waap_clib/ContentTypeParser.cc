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

#include "ContentTypeParser.h"
#include "Waf2Util.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_CONTENT_TYPE);

const std::string ContentTypeParser::m_parserName = "contentTypeParser";

int ContentTypeParser::onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth)
{
    dbgTrace(D_WAAP_PARSER_CONTENT_TYPE) << "ContentTypeParser::onKv(): " << std::string(v, v_len);
    assert((flags & BUFFERED_RECEIVER_F_BOTH) == BUFFERED_RECEIVER_F_BOTH);

    if (ctParserState == CTP_STATE_CONTENT_TYPE) {
        contentTypeDetected = std::string(k, k_len);
        dbgTrace(D_WAAP_PARSER_CONTENT_TYPE) << "ContentTypeParser::onKv(): contentTypeDetected: '" <<
            contentTypeDetected << "'";
        ctParserState = CTP_STATE_CONTENT_TYPE_PARAMS;
    } else if (ctParserState == CTP_STATE_CONTENT_TYPE_PARAMS) {
        if (my_strincmp(k, "boundary", k_len)) {
            boundaryFound = std::string(v, v_len);
        }
    } else {
        // This should never occur
        m_error = true;
        dbgWarning(D_WAAP_PARSER_CONTENT_TYPE) << "ContentTypeParser::onKv(): '" << std::string(v, v_len) <<
            "': BUG: Unknown content type found: " << ctParserState;
    }

    return 0; // ok
}

ContentTypeParser::ContentTypeParser() :
    ctParserState(CTP_STATE_CONTENT_TYPE),
    m_rcvr(*this),
    m_hvp(m_rcvr),
    m_error(false)
{}

size_t ContentTypeParser::push(const char *data, size_t data_len)
{
    dbgTrace(D_WAAP_PARSER_CONTENT_TYPE) << "ContentTypeParser::push(): processing content type";
    // Initialize state
    ctParserState = CTP_STATE_CONTENT_TYPE;
    contentTypeDetected = "";
    boundaryFound = "";
    // Execute parsing
    return m_hvp.push(data, data_len);
}

void ContentTypeParser::finish()
{
    return m_hvp.finish();
}

const std::string &
ContentTypeParser::name() const
{
    return m_parserName;
}

bool ContentTypeParser::error() const
{
    return m_error;
}
