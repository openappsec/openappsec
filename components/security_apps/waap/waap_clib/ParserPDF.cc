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

#include "ParserPDF.h"
#include "Waf2Util.h"
#include "debug.h"
#include <string.h>

USE_DEBUG_FLAG(D_WAAP_PARSER_PDF);
USE_DEBUG_FLAG(D_WAAP);

const std::string ParserPDF::m_parserName = "ParserPDF";
const char* PDF_TAIL = "%%EOF";

ParserPDF::ParserPDF(
    IParserStreamReceiver &receiver,
    size_t parser_depth
) :
    m_receiver(receiver),
    m_state(s_start),
    m_parser_depth(parser_depth)
{}

ParserPDF::~ParserPDF()
{}

size_t
ParserPDF::push(const char *buf, size_t len)
{
    dbgTrace(D_WAAP_PARSER_PDF)
        << "buf="
        << buf
        << "len="
        << len;

    const char *c;

    if (m_state == s_error) {
        return 0;
    }
    if (len == 0)
    {
        dbgTrace(D_WAAP_PARSER_PDF) << "ParserPDF::push(): end of stream. m_state=" << m_state;

        if (m_state == s_end) {
            m_receiver.onKvDone();
        } else {
            m_state = s_error;
        }
        return 0;
    }

    switch (m_state) {
            case s_start:
                m_state = s_body;
                CP_FALL_THROUGH;
            case s_body:
                c = strstr(buf + len - MAX_TAIL_LOOKUP, PDF_TAIL);
                dbgTrace(D_WAAP_PARSER_PDF) << "ParserPDF::push(): c=" << c;
                if (c) {
                    m_state = s_end;
                    CP_FALL_THROUGH;
                } else {
                    break;
                }
            case s_end:
                if (m_receiver.onKey("PDF", 3) != 0) {
                    m_state = s_error;
                    return 0;
                }
                if (m_receiver.onValue("", 0) != 0) {
                    m_state = s_error;
                    return 0;
                }
                break;
            case s_error:
                break;
            default:
                dbgTrace(D_WAAP_PARSER_PDF) << "ParserPDF::push(): unknown state: " << m_state;
                m_state = s_error;
                return 0;
    }

    return len;
}


void ParserPDF::finish()
{
    push(NULL, 0);
}

const std::string& ParserPDF::name() const
{
    return m_parserName;
}

bool ParserPDF::error() const
{
    return m_state == s_error;
}
