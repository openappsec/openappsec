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

#include "ParserMultipartForm.h"
#include "ParserHdrValue.h"
#include "Waf2Util.h"
#include "debug.h"
#include <stdlib.h>
#include <ctype.h>


USE_DEBUG_FLAG(D_WAAP_PARSER_MULTIPART_FORM);

#define LF 10
#define CR 13

const std::string ParserMultipartForm::m_parserName = "ParserMultipartForm";

int ParserMultipartForm::HdrValueAnalyzer::onKv(
    const char* k,
    size_t k_len,
    const char* v,
    size_t v_len,
    int flags,
    size_t parser_depth
    )
{
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "HdrValueAnalyzer::onKv(): k='%.*s' v='%.*s'" << (int)k_len << v;
    assert((flags & BUFFERED_RECEIVER_F_BOTH) == BUFFERED_RECEIVER_F_BOTH);

    if (my_strincmp(k, "name", k_len)) {
        m_partName = std::string(v, v_len);
    }

    return 0;
}

void ParserMultipartForm::HdrValueAnalyzer::clear() {
    m_partName.clear();
}

ParserMultipartForm::ParserMultipartForm(
    IParserStreamReceiver &receiver, size_t parser_depth, const char *boundary, size_t boundary_len
) :
    m_receiver(receiver),
    m_partIdx(0),
    state(s_start),
    index(0),
    boundary_length(boundary_len + 2),
    lookbehind(NULL),
    multipart_boundary(NULL),
    m_headerValueParser(NULL),
    m_hdrValueAnalyzerBufferedReceiver(m_hdrValueAnalyzer),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM)
        << "ParserMultipartForm::ParserMultipartForm() parser_depth="
        << parser_depth;
    boundary_len += 2; // two hyphens will be prepended to boundary string provided

    multipart_boundary = (char*)malloc(boundary_len + boundary_len + 9);
    if (multipart_boundary == NULL) {
        dbgWarning(D_WAAP_PARSER_MULTIPART_FORM) <<
            "ParserMultipartForm::ParserMultipartForm(): failed allocation of multipart_boundary buffer.";
        state = s_error;
        return;
    }
    // prepend two hyphens to boundary string provided
    multipart_boundary[0] = '-';
    multipart_boundary[1] = '-';
    memcpy(multipart_boundary + 2, boundary, boundary_len - 2);
    multipart_boundary[boundary_len] = 0;
    lookbehind = (multipart_boundary + boundary_length + 1);
}

ParserMultipartForm::~ParserMultipartForm() {
    if (multipart_boundary != NULL) {
        free(multipart_boundary);
    }
}

size_t ParserMultipartForm::push(const char* buf, size_t len) {
    size_t i = 0;
    size_t mark = 0;
    char c, cl;
    int is_last = 0;

    if (multipart_boundary == NULL) {
        dbgWarning(D_WAAP_PARSER_MULTIPART_FORM) <<
            "ParserMultipartForm::push(): can't parse. multipart_boundary=NULL.";
        state = s_error;
        return 0;
    }

    // Detect end of stream
    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): len = 0";
        // end of stream
        if (state != s_end) {
            dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) <<
                "ParserMultipartForm::push(): MIME stream finished while inside part";
            state = s_error;
            return 0;
        }
    }

    while (i < len) {
        c = buf[i];
        is_last = (i == (len - 1));
        switch (state) {
            case s_start:
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_start";
                index = 0;
                state = s_start_boundary;

                // fallthrough //
                CP_FALL_THROUGH;
            case s_start_boundary: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_start_boundary";
                if (index == boundary_length) {
                    if (c != CR) {
                        dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) <<
                            "ParserMultipartForm::push(): didn't get CR character";
                        state = s_error;
                        return i;
                    }
                    index++;
                    break;
                }
                else if (index == (boundary_length + 1)) {
                    if (c != LF) {
                        dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) <<
                            "ParserMultipartForm::push(): didn't get LF character";
                        state = s_error;
                        return i;
                    }
                    index = 0;
                    if (on_form_part_begin() != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_key_start;
                    break;
                }
                if (c != multipart_boundary[index]) {
                    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) <<
                        "ParserMultipartForm::push(): boundary check failed at index=" << index <<
                        " char '" << c << "', must be '" << multipart_boundary[index] << "'";
                    state = s_error;
                    return i;
                }
                index++;
                break;
            }
            case s_key_start: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_key_start";
                mark = i;
                state = s_key;
                // fallthrough //
                CP_FALL_THROUGH;
            }
            case s_key: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_key";
                if (c == CR) {
                    state = s_headers_almost_done;
                    break;
                }

                if (c == ':') {
                    if (on_form_part_hdr_key(buf + mark, i - mark) != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_value_start;
                    break;
                }

                cl = tolower(c);
                if ((c != '-') && (cl < 'a' || cl > 'z')) {
                    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) <<
                        "ParserMultipartForm::push(): invalid character in header name: " << int(c);
                    state = s_error;
                    return i;
                }
                if (is_last) {
                    if (on_form_part_hdr_key(buf + mark, (i - mark) + 1) != 0) {
                        state = s_error;
                        return i;
                    }
                }
                break;
            }
            case s_headers_almost_done: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_headers_almost_done";
                if (c != LF) {
                    state = s_error;
                    return i;
                }

                state = s_part_start;
                break;
            }
            case s_value_start: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_value_start";
                if (c == ' ') {
                    break;
                }

                mark = i;
                state = s_value;

                // fallthrough //
                CP_FALL_THROUGH;
            }
            case s_value: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_value";
                if (c == CR) {
                    if (on_form_part_hdr_value(buf + mark, i - mark) != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_value_almost_done;
                    break;
                }
                if (is_last) {
                    if (on_form_part_hdr_value(buf + mark, (i - mark) + 1) != 0) {
                        state = s_error;
                        return i;
                    }
                }
                break;
            }
            case s_value_almost_done: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_value_almost_done";
                if (c != LF) {
                    state = s_error;
                    return i;
                }
                state = s_key_start;
                if (this->on_form_part_hdr_kv_done() != 0) {
                    state = s_error;
                    return i;
                }
                break;
            }
            case s_part_start: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_start";
                if (on_form_headers_complete() != 0) {
                    state = s_error;
                    return i;
                }
                mark = i;
                state = s_part;

                // fallthrough //
                CP_FALL_THROUGH;
            }
            case s_part: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part";
                if (c == CR) {
                    if (on_form_part_data(buf + mark, i - mark) != 0) {
                        state = s_error;
                        return i;
                    }
                    mark = i;
                    state = s_part_almost_boundary;
                    lookbehind[0] = CR;
                    break;
                }
                if (is_last) {
                    if (on_form_part_data(buf + mark, (i - mark) + 1) != 0) {
                        state = s_error;
                        return i;
                    }
                }
                break;
            }
            case s_part_almost_boundary: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_almost_boundary";
                if (c == LF) {
                    state = s_part_boundary;
                    lookbehind[1] = LF;
                    index = 0;
                    break;
                }
                if (on_form_part_data(lookbehind, 1) != 0) {
                    state = s_error;
                    return i;
                }
                state = s_part;
                mark = i--;
                break;
            }
            case s_part_boundary: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_boundary";
                if (multipart_boundary[index] != c) {
                    if (on_form_part_data(lookbehind, 2 + index) != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_part;
                    mark = i--;
                    break;
                }
                lookbehind[2 + index] = c;
                if ((++index) == boundary_length) {
                    if (on_form_part_end() != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_part_almost_end;
                }
                break;
            }
            case s_part_almost_end: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_almost_end";
                if (c == '-') {
                    state = s_part_final_hyphen;
                    break;
                }
                if (c == CR) {
                    state = s_part_end;
                    break;
                }
                state = s_error;
                return i;
            }
            case s_part_final_hyphen: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_final_hyphen";
                if (c == '-') {
                    if (on_form_body_end() != 0) {
                        state = s_error;
                        return i;
                    }
                    state = s_end;
                    break;
                }
                state = s_error;
                return i;
            }
            case s_part_end: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_part_end";
                if (c == LF) {
                    state = s_key_start;
                    if (on_form_part_begin() != 0) {
                        state = s_error;
                        return i;
                    }
                    break;
                }
                state = s_error;
                return i;
            }
            case s_end: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_end";
                break;
            }
            case s_error: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): s_error";
                return 0;
            }

            default: {
                dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::push(): unknown state: " << state;
                state = s_error;
                return 0;
            }
        }
        ++i;
    }

    return len;
}

void ParserMultipartForm::finish() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::finish():";
    push(NULL, 0);
}

const std::string &
ParserMultipartForm::name() const {
    return m_parserName;
}

bool ParserMultipartForm::error() const {
    return state == s_error;
}

// MIME form parsing
int ParserMultipartForm::on_form_part_hdr_key(const char* k, size_t k_len) {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_hdr_key(): '" <<
        std::string(k, k_len) << "'";
    m_hdrName += std::string(k, k_len);
    return 0; // ok
}

int ParserMultipartForm::on_form_part_hdr_value(const char* v, size_t v_len) {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_hdr_value(): '" <<
        std::string(v, v_len) << "'";

    // This function could be called multiple times, only on the first call we allocated m_headerValueParser
    if (!m_headerValueParser) {
        // The m_hdrValueAnalyzer instance will receive information about part headers
        // and extract information from them, like the part name (if available).
        m_headerValueParser = new ParserHdrValue(m_hdrValueAnalyzerBufferedReceiver);
    }

    // push pieces of header value to header value processor/analyzer
    if (m_headerValueParser) {
        m_headerValueParser->push(v, v_len);
    }

    return 0; // ok
}

int ParserMultipartForm::on_form_part_hdr_kv_done() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_hdr_kv_done():";

    // finish any header value parsing in progress. the collected data is stored in m_hdrValueAnalyzer object.
    if (m_headerValueParser) {
        m_headerValueParser->finish();
        delete m_headerValueParser;
        m_headerValueParser = NULL;
    }

    // collect parsed information about header value only If current header name is "Content-Disposition"
    // the reason this check is done here is only because (at least by the Parsers API protocol)
    // the part header name was not ready until this point.
    if (my_stricmp(m_hdrName.c_str(), "content-disposition")) {
        // the m_hdrValueAnalyzer contains information (like part name) extracted from the
        // Content-Disposition header. Lets collect it now.
        m_partName = m_hdrValueAnalyzer.getPartName();

        // if part name could be extracted from part header - use it,
        // otherwise name "anonymous" part "part-NNN" where NNN is part number within the MIME message
        if (m_partName.empty()) {
            char buf[128];
            snprintf(buf, sizeof(buf), "part-%lu", (unsigned long int)m_partIdx);
            m_partName = buf;
        }
    }

    // reset m_hdrValueAnalyzer object state before next part header.
    // we already collected all relevant information from it above.
    m_hdrValueAnalyzer.clear();

    // also clear accumulated part header name string before next part header
    m_hdrName = "";
    return 0; // ok
}

int ParserMultipartForm::on_form_headers_complete() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_headers_complete():";

    int rc = m_receiver.onKey(m_partName.data(), m_partName.size());
    m_hdrValueAnalyzer.clear();
    return rc;
}

int ParserMultipartForm::on_form_part_begin() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_begin():";
    // count parts
    m_partIdx++;
    // reset currently known part name before switching to next part
    m_partName = "";
    return 0; // ok
}

int ParserMultipartForm::on_form_part_end() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_end():";
    return m_receiver.onKvDone();
}

int ParserMultipartForm::on_form_part_data(const char* at, size_t length) {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_part_data(): '" <<
        std::string(at, length) << "'";
    return m_receiver.onValue(at, length);
}

int ParserMultipartForm::on_form_body_end() {
    dbgTrace(D_WAAP_PARSER_MULTIPART_FORM) << "ParserMultipartForm::on_form_body_end():";
    return 0; // ok
}
