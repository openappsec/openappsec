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
#include <vector>
#include <tuple>

using namespace std;
using Waap::Util::BinaryFileType;

USE_DEBUG_FLAG(D_WAAP_PARSER_BINARY_FILE);
USE_DEBUG_FLAG(D_WAAP);

const string ParserBinaryFile::m_parserName = "ParserBinaryFile";

struct BinarySignature {
    string head;
    string tail;
    string b64_prefix;            // empty disables base64 detection
    bool (*validate)(const string &);  // nullptr = no post-decode validation
};

static bool isValidJpegFirstMarker(const string &decoded);

static const map<BinaryFileType, BinarySignature> m_file_signatures = {
    {BinaryFileType::FILE_TYPE_PNG, {
        string("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"),
        string("\x49\x45\x4e\x44\xae\x42\x60\x82"),
        "iVBORw0",
        nullptr}},
    {BinaryFileType::FILE_TYPE_JPEG, {
        string("\xff\xd8\xff"),
        string("\xff\xd9"),
        "/9j/",
        isValidJpegFirstMarker}},
    {BinaryFileType::FILE_TYPE_PDF, {
        string("%PDF-"),
        string("%%EOF"),
        "JVBER",
        nullptr}},
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

// Returns the number of decoded bytes written (up to outCapacity), or 0 on invalid base64.
// '<0' tests below collapse padding (-2) and invalid (-1) into the same stop condition.
static size_t decodeBase64Header(const string &s, size_t pos, char *out, size_t outCapacity)
{
    size_t remaining = s.size() - pos;
    size_t b64Needed = ((outCapacity + 2) / 3) * 4;
    size_t b64Len = min(remaining, b64Needed);
    b64Len = (b64Len / 4) * 4;
    if (b64Len < 4) return 0;

    size_t decoded = 0;
    for (size_t i = 0; i + 3 < b64Len && decoded < outCapacity; i += 4) {
        int8_t a = base64_table[(unsigned char)s[pos + i]];
        int8_t b = base64_table[(unsigned char)s[pos + i + 1]];
        int8_t c = base64_table[(unsigned char)s[pos + i + 2]];
        int8_t d = base64_table[(unsigned char)s[pos + i + 3]];
        if (a < 0 || b < 0) return 0;
        out[decoded++] = (char)((a << 2) | (b >> 4));
        if (decoded < outCapacity && c >= 0) {
            out[decoded++] = (char)(((b & 0x0F) << 4) | (c >> 2));
            if (decoded < outCapacity && d >= 0) {
                out[decoded++] = (char)(((c & 0x03) << 6) | d);
            }
        }
    }
    return decoded;
}

// Rejects inputs where a recognized binary header is followed by non-base64 bytes
// (otherwise silently dropped by ParserBinaryFile, enabling XSS bypass).
static bool
isPureBase64FromOffset(const string &s, size_t pos)
{
    int paddingSeen = 0;
    for (size_t i = pos; i < s.size(); i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '=') {
            if (++paddingSeen > 2) return false;
        } else if (paddingSeen > 0 || !Waap::Util::isBase64AlphaChar(c)) {
            return false;
        }
    }
    return true;
}

// The JPEG header (FF D8 FF) is only 4 base64 chars, so the prefix check alone is too weak.
// Validates the byte after SOI is a real first-segment marker; rejects e.g. "/9j/+cat+...".
static bool
isValidJpegFirstMarker(const string &decoded)
{
    if (decoded.size() < 4) return false;
    unsigned char m = (unsigned char)decoded[3];
    bool valid =
        (m >= 0xE0 && m <= 0xEF)    // APP0-APP15 (JFIF, EXIF, etc)
        || (m >= 0xC0 && m <= 0xCF) // SOF markers
        || m == 0xDB                // DQT
        || m == 0xDA                // SOS
        || m == 0xDD                // DRI
        || m == 0xFE;               // COM
    if (!valid) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE)
            << "JPEG header matched but marker type byte[3]=0x" << hex << (unsigned int)m
            << " is not a recognized JPEG marker";
    }
    return valid;
}

BinaryFileType
ParserBinaryFile::detectBinaryBase64Prefix(const string &s, size_t pos)
{
    size_t remaining = s.size() - pos;

    for (const auto &entry : m_file_signatures) {
        const BinaryFileType type = entry.first;
        const BinarySignature &sig = entry.second;

        if (sig.b64_prefix.empty()) continue;
        if (remaining < sig.b64_prefix.size()) continue;
        if (s.compare(pos, sig.b64_prefix.size(), sig.b64_prefix) != 0) continue;

        // Prefixes are 1:1 with types: any failure below is terminal, no other prefix can match.
        char headerBuf[MAX_HEADER_LOOKUP];
        size_t decodedLen = decodeBase64Header(s, pos, headerBuf, MAX_HEADER_LOOKUP);
        if (decodedLen < MIN_HEADER_LOOKUP) return BinaryFileType::FILE_TYPE_NONE;

        string decoded(headerBuf, decodedLen);
        if (decoded.size() < sig.head.size() ||
            decoded.compare(0, sig.head.size(), sig.head) != 0) {
            return BinaryFileType::FILE_TYPE_NONE;
        }

        if (sig.validate && !sig.validate(decoded)) return BinaryFileType::FILE_TYPE_NONE;

        if (!isPureBase64FromOffset(s, pos)) {
            dbgTrace(D_WAAP_PARSER_BINARY_FILE)
                << "Rejecting binary detection: input has non-base64 bytes after the header";
            return BinaryFileType::FILE_TYPE_NONE;
        }

        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "Verified known binary file from base64 data, type=" << type;
        return type;
    }

    return BinaryFileType::FILE_TYPE_NONE;
}

BinaryFileType
ParserBinaryFile::detectBinaryFileHeader(const string &buf)
{
    if (buf.size() < MIN_HEADER_LOOKUP) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "Buffer size too small (" << buf.size() << ")";
        return BinaryFileType::FILE_TYPE_NONE;
    }
    const string searchStr = buf.substr(0, MAX_HEADER_LOOKUP);
    for (const auto &entry : m_file_signatures) {
        const string &head = entry.second.head;
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
    if (m_file_signatures.find(m_file_type) == m_file_signatures.end()) {
        dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "unknown file type: " << m_file_type;
        m_state = s_error;
        return 0;
    }
    const string tail = m_file_signatures.at(m_file_type).tail;

    switch (m_state) {
            case s_start:
                m_state = s_body;
                CP_FALL_THROUGH;
            case s_body:
                if (m_is_base64) {
                    dbgTrace(D_WAAP_PARSER_BINARY_FILE) << "parsing base64";
                    bool keepParsing = true;
                    for (size_t i = 0; i < len; i++) {
                        bool isB64AlphaChar = Waap::Util::isBase64AlphaChar(buf[i]);
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
                    size_t tail_lookup_offset = (len > MAX_TAIL_LOOKUP) ? len - MAX_TAIL_LOOKUP : 0;
                    c = static_cast<const char *>(memmem(buf + tail_lookup_offset,
                        len - tail_lookup_offset,
                        tail.c_str(),
                        tail.size()));
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
