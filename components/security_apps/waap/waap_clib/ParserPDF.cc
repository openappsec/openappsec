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
const size_t PDF_TAIL_LEN = 5;

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
        << "buf='"
        << std::string(buf, std::min((size_t)200, len))
        << (len > 200 ? "..." : "")
        << "' len="
        << len;

    if (m_state == s_error) {
        return 0;
    }

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_PDF) << "ParserPDF::push(): end of stream. m_state=" << m_state;
        if (m_state == s_body && m_tailOffset >= PDF_TAIL_LEN) {
            if (m_receiver.onKey("PDF", 3) != 0) {
                m_state = s_error;
                return 0;
            }
            if (m_receiver.onValue("", 0) != 0) {
                m_state = s_error;
                return 0;
            }
            m_receiver.onKvDone();
        } else {
            m_state = s_error;
        }
        return 0;
    }

    size_t start = (len > MAX_PDF_TAIL_LOOKUP) ? len - MAX_PDF_TAIL_LOOKUP : 0;
    switch (m_state) {
            case s_start:
                m_state = s_body;
                CP_FALL_THROUGH;
            case s_body:
                for (size_t i = start; i < len; i++) {
                    dbgTrace(D_WAAP_PARSER_PDF)
                        << "ParserPDF::push(): m_tailOffset="
                        << m_tailOffset
                        << " buf[i]="
                        << buf[i];
                    if (m_tailOffset  <= PDF_TAIL_LEN - 1) {
                        if (buf[i] == PDF_TAIL[m_tailOffset]) {
                            m_tailOffset++;
                        } else {
                            m_tailOffset = 0;
                        }
                    } else {
                        if (buf[i] == '\r' || buf[i] == '\n' || buf[i] == ' ' || buf[i] == 0) {
                            m_tailOffset++;
                        } else {
                            m_tailOffset = 0;
                            i--;
                        }
                    }
                }
                dbgTrace(D_WAAP_PARSER_PDF)
                    << "ParserPDF::push()->s_body: m_tailOffset="
                    << m_tailOffset;
                break;
            case s_error:
                break;
            default:
                dbgTrace(D_WAAP_PARSER_PDF)
                    << "ParserPDF::push(): unknown state: "
                    << m_state;
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
