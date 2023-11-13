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

#ifndef __PARSER_MULTIPART_FORM_H__1c7eb4fa
#define __PARSER_MULTIPART_FORM_H__1c7eb4fa

#include "ParserBase.h"
#include "ParserHdrValue.h"
#include <boost/core/noncopyable.hpp>

class ParserMultipartForm : public ParserBase, boost::noncopyable
{
public:
    class HdrValueAnalyzer : public IParserReceiver
    {
    public:
        int onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth);
        void clear();
        const std::string &getPartName() const { return m_partName; }
    private:
        std::string m_partName;
    };

    ParserMultipartForm(
        IParserStreamReceiver &receiver,
        size_t parser_depth,
        const char *boundary,
        size_t boundary_len
        );
    virtual ~ParserMultipartForm();
    size_t push(const char *buf, size_t len);
    void finish();
    virtual const std::string &name() const;
    virtual bool error() const;
    virtual size_t depth() { return 1; }
private:
    enum state
    {
        s_start,
        s_start_boundary,
        s_key_start,
        s_key,
        s_headers_almost_done,
        s_value_start,
        s_value,
        s_value_almost_done,
        s_part_start,
        s_part,
        s_part_almost_boundary,
        s_part_boundary,
        s_part_almost_end,
        s_part_end,
        s_part_final_hyphen,
        s_end,
        s_error
    };

    // MIME form parsing
    int on_form_part_hdr_key(const char *k, size_t k_len);
    int on_form_part_hdr_value(const char *v, size_t v_len);
    int on_form_part_hdr_kv_done();
    int on_form_headers_complete();
    int on_form_part_begin();
    int on_form_part_end();
    int on_form_part_data(const char *at, size_t length);
    int on_form_body_end();

    IParserStreamReceiver &m_receiver;

    // index of currently processed part (0-based)
    size_t m_partIdx;

    enum state state;
    size_t index;
    size_t boundary_length;
    char* lookbehind;
    char *multipart_boundary;

    ParserHdrValue *m_headerValueParser;    // Part Header's value parser/dissector.
                                            // Reports dissected parts to m_hdrValueAnalyzer.
    HdrValueAnalyzer m_hdrValueAnalyzer;    // Receives and analyzes dissected parts of part header value,
                                            // and extracts information like part name from it.
    BufferedReceiver m_hdrValueAnalyzerBufferedReceiver;    // Buffers partial header value data before
                                                            // it is available to m_hdrValueAnalyzer.
    std::string m_hdrName; // Current part header name (accumulated until on_form_part_hdr_kv_done() is called.
    std::string m_partName; // Part name

    static const std::string m_parserName;
    size_t m_parser_depth;
};

#endif // __PARSER_MULTIPART_FORM_H__1c7eb4fa
