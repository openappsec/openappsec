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

#include "ParserGzip.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER_GZIP);

const std::string ParserGzip::m_parserName = "ParserGzip";

ParserGzip::ParserGzip(IParserStreamReceiver &receiver, size_t parser_depth)
:m_receiver(receiver), m_key("gzip"), m_state(s_start), m_stream(nullptr) {
}

ParserGzip::~ParserGzip() {
    if (m_stream != nullptr) {
        finiCompressionStream(m_stream);
        m_stream = nullptr;
    }
}

size_t ParserGzip::push(const char *buf, size_t len) {
    dbgTrace(D_WAAP_PARSER_GZIP) << "len=" << (unsigned long int)len << ")";

    if (len == 0) {
        dbgTrace(D_WAAP_PARSER_GZIP) << "end of data signal! m_state=" << m_state;

        // flush
        if (m_state != s_start) { // only emit if at least something was pushed
            if (m_receiver.onKvDone() != 0) {
                m_state = s_error;
            }
        }

        return 0;
    }
    DecompressionResult res;
    switch (m_state) {
    case s_start:
        dbgTrace(D_WAAP_PARSER_GZIP) << "s_start";
        if (m_receiver.onKey(m_key.data(), m_key.size()) != 0) {
            m_state = s_error;
            return 0;
        }
        m_stream = initCompressionStream();
        m_state = s_forward;
        // fallthrough //
        CP_FALL_THROUGH;
    case s_forward:
        dbgTrace(D_WAAP_PARSER_GZIP) << "s_forward";
        res = decompressData(
            m_stream,
            len,
            reinterpret_cast<const unsigned char *>(buf));
        dbgTrace(D_WAAP_PARSER_GZIP) << "res: " << res.ok
            << ", size: " << res.num_output_bytes
            << ", is last: " << res.is_last_chunk;

        if (!res.ok) {
            m_state = s_error;
            break;
        }

        if (res.num_output_bytes != 0 &&
                m_receiver.onValue(reinterpret_cast<const char *>(res.output), res.num_output_bytes) != 0) {
            m_state = s_error;
            break;
        }

        if (res.is_last_chunk) {
            m_state = s_done;
            break;
        }
        break;
    case s_done:
        if (len > 0) {
            dbgTrace(D_WAAP_PARSER_GZIP) << " unexpected data after completion, len=" << len;
            m_state = s_error;
            return 0; // Return 0 to indicate error
        }
        break;
    case s_error:
        dbgTrace(D_WAAP_PARSER_GZIP) << "s_error";
        return 0;
    }

    return len;
}

void ParserGzip::finish() {
    push(NULL, 0);
    if (m_state != s_done) {
        m_state = s_error;
        return;
    }
}

const std::string &
ParserGzip::name() const {
    return m_parserName;
}

bool ParserGzip::error() const {
    return m_state == s_error;
}
