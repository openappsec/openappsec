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

#include "ParserBase.h"
#include <string.h>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_PARSER);

// Max size for key and value that can be stored in memory (per thread)
#define MAX_KEY_SIZE 64*1024
#define MAX_VALUE_SIZE 64*1024

BufferedReceiver::BufferedReceiver(IParserReceiver &receiver, size_t parser_depth) :
    m_receiver(receiver),
    m_flags(BUFFERED_RECEIVER_F_FIRST),
    m_parser_depth(parser_depth)
{
    dbgTrace(D_WAAP_PARSER)
    << "parser_depth="
    << parser_depth;
}

int BufferedReceiver::onKey(const char *k, size_t k_len)
{
    dbgTrace(D_WAAP_PARSER)
        << "Entering BufferedReceiver::onKey with values: \n"
        << "\tkey = "
        << k
        << "\n\tk_len = "
        << k_len
        << "\n\tm_key = "
        << m_key
        << "\n\t m_key_size = "
        << m_key.size()
        << "\n\t parser_depth = "
        << m_parser_depth;
    if (m_key.size() + k_len < MAX_KEY_SIZE) {
        m_key += std::string(k, k_len);
    }

    return 0;
}

int BufferedReceiver::onValue(const char *v, size_t v_len)
{
    int rc = 0;
    dbgTrace(D_WAAP_PARSER)
        << "Entering BufferedReceiver::onValue with values: \n"
        << "\tvalue = "
        << v
        << "\n\tv_len = "
        << v_len
        << "\n\tm_value = "
        << m_value
        << "\n\t m_value_size = "
        << m_value.size()
        << "\n\t parser_depth = "
        << m_parser_depth;
    while (v_len > 0) {
        // Move data from buffer v to accumulated m_value string in an attempt to fill m_value to its max size
        size_t bytesToFill = std::min(v_len, MAX_VALUE_SIZE - m_value.size());
        m_value += std::string(v, bytesToFill);
        // Update v and v_len (input buffer) to reflect that we already consumed part (or all) of it
        v += bytesToFill;
        v_len -= bytesToFill;

        // Only push full buffers to the m_receiver
        if (m_value.size() == MAX_VALUE_SIZE) {
            // The first full-size buffer will be pushed with BUFFERED_RECEIVER_F_FIRST flag
            dbgTrace(D_WAAP_PARSER)
                << " The first full-size buffer will be pushed with BUFFERED_RECEIVER_F_FIRST flag"
                << "calling onKv() while m_flags = "
                << m_flags;
            int tempRc= m_receiver.onKv(
                m_key.data(),
                m_key.size(),
                m_value.data(),
                m_value.size(),
                m_flags,
                m_parser_depth
                );
            if (tempRc != 0) {
                rc = tempRc;
            }
            // Clear accumulted buffer that is already pushed (and processed) by the receiver
            m_value.clear();
            // Clear the "first buffer" flag for all the next buffers
            m_flags &= ~BUFFERED_RECEIVER_F_FIRST;
        }
    }

    return rc;
}

int BufferedReceiver::onKvDone()
{
    m_flags |= BUFFERED_RECEIVER_F_LAST; // set flag
    // Call onKv on the remainder of the buffer not yet pushed to the receiver
    // This must be called even if m_value is empty in order to signal the BUFFERED_RECEIVER_F_LAST flag to the
    // receiver!
    dbgTrace(D_WAAP_PARSER)
        << " Call onKv on the remainder of the buffer not yet pushed to the receiver "
        << "calling onKv()";
    int rc = onKv(m_key.data(), m_key.size(), m_value.data(), m_value.size(), m_flags, m_parser_depth);

    // Reset the object's state to allow reuse for other parsers
    clear();
    return rc;
}

int BufferedReceiver::onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth)
{
    return m_receiver.onKv(k, k_len, v, v_len, flags, parser_depth);
}

void BufferedReceiver::clear()
{
    m_flags = BUFFERED_RECEIVER_F_FIRST;
    m_key.clear();
    m_value.clear();
}
