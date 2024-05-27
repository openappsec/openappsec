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

#include "ParserBinaryFile.h"
#include "Waf2Util.h"
#include "debug.h"
#include <string.h>
#include <map>
#include <tuple>

using namespace std;
using Waap::Util::BinaryFileType;

USE_DEBUG_FLAG(D_WAAP_PARSER_BINARY_FILE);
USE_DEBUG_FLAG(D_WAAP);

const string ParserBinaryFile::m_parserName = "ParserBinaryFile";

static const map<BinaryFileType, pair<string, string>> m_head_tail_map = {
    {BinaryFileType::FILE_TYPE_PNG,
        {string("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"), // PNG
        string("\x49\x45\x4e\x44\xae\x42\x60\x82")}},  // IEND
    {BinaryFileType::FILE_TYPE_JPEG,
        {string("\xff\xd8\xff"),
        string("\xff\xd9")}},
    {BinaryFileType::FILE_TYPE_PDF,
        {string("%PDF-"),
        string("%%EOF")}}
};

ParserBinaryFile::ParserBinaryFile(
    IParserStreamReceiver &receiver,
    size_t parser_depth,
    bool is_base64,
    BinaryFileType file_type
) :
    m_receiver(receiver),
    m_state(s_start),
    m_parser_depth(parser_depth),
    m_is_base64(is_base64),
    m_file_type(file_type)
{}

ParserBinaryFile::~ParserBinaryFile()
{}

BinaryFileType
ParserBinaryFile::detectBinaryFileHeader(const string &buf)
{
    if (buf.size() < MIN_HEADER_LOOKUP) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "Buffer size too small (" << buf.size() << ")";
        return BinaryFileType::FILE_TYPE_NONE;
    }
    const string searchStr = buf.substr(0, MAX_HEADER_LOOKUP);
    for (const auto &entry : m_head_tail_map) {
        const string &head = entry.second.first;
        size_t pos = searchStr.find(head);
        if (pos != string::npos) {
            if (buf.size() - pos >= MIN_HEADER_LOOKUP) {
                dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "Found. type=" << entry.first;
                return entry.first;
            } else {
                dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "Remaining size after header is too small";
                return BinaryFileType::FILE_TYPE_NONE;
            }
        }
    }
    return BinaryFileType::FILE_TYPE_NONE;
}


size_t
ParserBinaryFile::push(const char *buf, size_t len)
{
    dbgTrace(D_WAAP_PARSER_BINARY_FILE)
        << "buf="
        << buf
        << "len="
        << len;

    const char *c;

    if (m_state == s_error) {
        return 0;
    }
    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "end of stream. m_state=" << m_state;

        if (m_state == s_end) {
            m_receiver.onKvDone();
        } else if (m_is_base64) {
            dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "finished parsing";
            if (m_receiver.onKey("BinaryFileSkip", 14) != 0) {
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
    if (m_head_tail_map.find(m_file_type) == m_head_tail_map.end()) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "unknown file type: " << m_file_type;
        m_state = s_error;
        return 0;
    }
    const string tail = m_head_tail_map.at(m_file_type).second;

    switch (m_state) {
            case s_start:
                m_state = s_body;
                CP_FALL_THROUGH;
            case s_body:
                if (m_is_base64) {
                    dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "parsing base64";
                    bool keepParsing = true;
                    for (size_t i = 0; i < len; i++) {
                        bool isB64AlphaChar =
                            Waap::Util::isAlphaAsciiFast(buf[i]) || isdigit(buf[i]) || buf[i] == '/' || buf[i] == '+';
                        if (buf[i] == '=') {
                            dbgTrace(D_WAAP_PARSER_BINARY_FILE)
                                << "base64 padding found (offset=" << i << "). end of stream.";
                            m_state = s_end;
                            keepParsing = false;
                            break;
                        } else if (!isB64AlphaChar) {
                            dbgTrace(D_WAAP_PARSER_BINARY_FILE)
                                << "non-base64 char found (c=" << buf[i] << ",offset=" << i << "). return error";
                            m_state = s_error;
                            return 0;
                        }
                    }
                    if (keepParsing) { // keep "parsing" on next call to push()
                        break;
                    }
                } else {
                    dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "parsing binary. Searching for tail: " << tail;
                    c = strstr(buf + len - tail.size(), tail.c_str());
                    dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "search result: c=" << c;
                    if (c) {
                        m_state = s_end;
                    } else { // keep "parsing" on next call to push()
                        break;
                    }
                }
                CP_FALL_THROUGH;
            case s_end:
                dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "finished parsing";
                if (m_receiver.onKey("BinaryFileSkip", 14) != 0) {
                    m_state = s_error;
                    return 0;
                }
                if (m_receiver.onValue("", 0) != 0) {
                    m_state = s_error;
                    return 0;
                }
                break;
            case s_error:
                dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "error detected";
                break;
            default:
                dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "unknown state: " << m_state;
                m_state = s_error;
                return 0;
    }

    return len;
}


void ParserBinaryFile::finish()
{
    push(NULL, 0);
}

const string& ParserBinaryFile::name() const
{
    return m_parserName;
}

bool ParserBinaryFile::error() const
{
    return m_state == s_error;
}
