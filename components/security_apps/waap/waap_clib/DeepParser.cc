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

// #define WAF2_LOGGING_ENABLE
#include "WaapValueStatsAnalyzer.h"
#include "DeepParser.h"
#include "ParserUrlEncode.h"
#include "PHPSerializedDataParser.h"
#include "ParserJson.h"
#include "ParserGql.h"
#include "ParserConfluence.h"
#include "ParserXML.h"
#include "ParserHTML.h"
#include "ParserBinary.h"
#include "ParserMultipartForm.h"
#include "ParserPercentEncode.h"
#include "ParserPairs.h"
#include "ParserDelimiter.h"
#include "WaapAssetState.h"
#include "Waf2Regex.h"
#include "Waf2Util.h"
#include "debug.h"
#include "i_transaction.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_WAAP_DEEP_PARSER);
USE_DEBUG_FLAG(D_WAAP_ULIMITS);
USE_DEBUG_FLAG(D_WAAP_STREAMING_PARSING);
USE_DEBUG_FLAG(D_OA_SCHEMA_UPDATER);

#define DONE_PARSING     0
#define FAILED_PARSING   -1
#define CONTINUE_PARSING 1
#define MAX_DEPTH        7

DeepParser::DeepParser(
    std::shared_ptr<WaapAssetState> pWaapAssetState, IParserReceiver &receiver, IWaf2Transaction *pTransaction
) :
    m_key("deep_parser"),
    m_pWaapAssetState(pWaapAssetState),
    m_pTransaction(pTransaction),
    m_receiver(receiver),
    m_depth(0),
    m_splitRefs(0),
    m_deepParserFlag(false),
    m_splitTypesStack(),
    m_multipart_boundary(""),
    m_globalMaxObjectDepth(std::numeric_limits<size_t>::max()),
    m_localMaxObjectDepth(0),
    m_globalMaxObjectDepthReached(false),
    m_is_wbxml(false)
{}

DeepParser::~DeepParser()
{}


void
DeepParser::setWaapAssetState(std::shared_ptr<WaapAssetState> pWaapAssetState)
{
    m_pWaapAssetState = pWaapAssetState;
}

void
DeepParser::clear()
{
    m_depth = 0;
    m_splitRefs = 0;
    kv_pairs.clear();
    m_key.clear();
    kv_pairs.clear();
    m_keywordInfo.clear();
    m_multipart_boundary = "";
}

size_t
DeepParser::depth() const
{
    return m_depth;
}

// Called when another key/value pair is ready
int
DeepParser::onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth)
{
    int rc = 0;
    m_depth++;

    dbgTrace(D_WAAP_DEEP_PARSER)
        << "DeepParser::onKv(): k='"
        << std::string(k, (int)k_len)
        << "' v='"
        << std::string(v, (int)v_len)
        << "'; depth="
        << m_depth
        << "; flags="
        << flags
        << " parser_depth: "
        << parser_depth
        << " v_len = "
        << v_len;
    // Decide whether to push/pop the value in the keystack.
    bool shouldUpdateKeyStack = (flags & BUFFERED_RECEIVER_F_UNNAMED) == 0;

    // Disable the flag so it doesn't propagate deeper.
    flags &= ~BUFFERED_RECEIVER_F_UNNAMED;

    if (m_depth > MAX_DEPTH) {
        std::string cur_val = std::string(v, v_len);
        dbgDebug(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): Recursion depth limit reached. recursion_depth="
            << m_depth;

        if (shouldUpdateKeyStack) {
            m_key.push(k, k_len);
        }
        rc = m_receiver.onKv(
            m_key.c_str(),
            strlen(m_key.c_str()),
            cur_val.data(),
            cur_val.size(),
            flags,
            parser_depth
            );
        m_depth--;
        return rc;
    }

    size_t currDepth = 0;
    if (!isGlobalMaxObjectDepthReached()) {
        for (const auto &parser : m_parsersDeque) {
            if (shouldEnforceDepthLimit(parser)) {
                currDepth += parser->depth();
            }
        }
    }

    if (currDepth > getLocalMaxObjectDepth()) {
        setLocalMaxObjectDepth(currDepth);
    }
    if (currDepth > getGlobalMaxObjectDepth()) {
        setGlobalMaxObjectDepthReached();
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "[USER LIMITS] DeepParser::onKv(): Object depth limit exceeded "
            << currDepth
            << "/"
            << getGlobalMaxObjectDepth()
            << " no. of parsers: "
            << m_parsersDeque.size();
        return DONE_PARSING;
    } else {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "[USER LIMITS] DeepParser::onKv(): current object depth "
            << currDepth
            << "/"
            << getGlobalMaxObjectDepth()
            << " no. of parsers: "
            << m_parsersDeque.size();
    }

    // Ignore when both key and value are empty
    if (k_len == 0 && v_len == 0) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): ignoring empty KV pair.";
        m_depth--;
        return DONE_PARSING;
    }
    if (shouldUpdateKeyStack) {
        m_key.push(k, k_len);
    }
    // Maintain dot-delimited key stack

    bool isUrlParamPayload = (m_key.first().size() == 9 && m_key.first() == "url_param");
    bool isRefererParamPayload = (m_key.first().size() == 13 && m_key.first() == "referer_param");
    bool isRefererPayload = (m_key.first().size() == 7 && m_key.first().find("referer") == 0);
    bool isUrlPayload = (m_key.first().size() == 3 && m_key.first().find("url") == 0);
    bool isHeaderPayload = (m_key.first().size() == 6 && m_key.first() == "header");
    bool isCookiePayload = (m_key.first().size() == 6 && m_key.first() == "cookie");
    bool isBodyPayload = (m_key.first().size() == 4 && m_key.first() == "body");

    // If csrf/antibot cookie - send to Waf2Transaction for collection of cookie value.
    if (m_depth == 1 && isCookiePayload && (m_key.str() == "x-chkp-csrf-token" || m_key.str() == "__fn1522082288")) {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): found: "
            << m_key.str()
            << "cookie - sending to Waf2Transaction to collect cookie value.";
        rc =
            m_receiver.onKv(
                m_key.c_str(),
                strlen(m_key.c_str()),
                cur_val.data(),
                cur_val.size(),
                flags,
                parser_depth
                );

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return rc;
    }

    // If csrf header - send to Waf2Transaction for collection of cookie value.
    if (m_depth == 1 && isHeaderPayload && m_key.str() == "x-chkp-csrf-token") {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): found csrf header - sending to Waf2Transaction to collect cookie value.";
        rc = m_receiver.onKv(
            m_key.c_str(),
            strlen(m_key.c_str()),
            cur_val.data(),
            cur_val.size(),
            flags,
            parser_depth
            );

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return rc;
    }

    // If csrf body - send to Waf2Transaction for collection of cookie value.
    if (isBodyPayload && m_key.str() == "x-chkp-csrf-token") {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER
        ) << "DeepParser::onKv(): found csrf form data - sending to Waf2Transaction to collect cookie value.";
        rc = m_receiver.onKv(
            m_key.c_str(),
            strlen(m_key.c_str()),
            cur_val.data(),
            cur_val.size(),
            flags,
            parser_depth
            );

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return rc;
    }

    // only report kv_pairs collected from the 1st recursion level
    // (and before b64 decoding, which is important since we don't want to see ".#base64" in parameter
    // names in this report.
    if (m_depth == 1) {
        if ((k_len > 0 || v_len > 0) && !isHeaderPayload && !isUrlPayload && !isRefererPayload &&
            !isRefererParamPayload && !isCookiePayload) {
            dbgTrace(D_WAAP_DEEP_PARSER) << " kv_pairs.push_back";
            kv_pairs.push_back(std::make_pair(std::string(k, k_len), std::string(v, v_len)));
        }
    }

    // TODO:: do we need to construct std::string for this in this function??
    std::string cur_val = std::string(v, v_len);

    // Detect and decode potential base64 chunks in the value before further processing

    bool base64ParamFound = false;
    dbgTrace(D_WAAP_DEEP_PARSER) << " ===Processing potential base64===";
    std::string decoded_val, decoded_key;
    base64_variants base64_status = Waap::Util::b64Test(cur_val, decoded_key, decoded_val);

    dbgTrace(D_WAAP_DEEP_PARSER)
        << " status = "
        << base64_status
        << " key = "
        << decoded_key
        << " value = "
        << decoded_val;

    switch (base64_status) {
        case SINGLE_B64_CHUNK_CONVERT:
            cur_val = decoded_val;
            base64ParamFound = true;
            break;
        case KEY_VALUE_B64_PAIR:
            // going deep with new pair in case value is not empty
            if (decoded_val.size() > 0) {
                cur_val = decoded_val;
                base64ParamFound = true;
                rc = onKv(
                    decoded_key.c_str(),
                    decoded_key.size(),
                    cur_val.data(),
                    cur_val.size(),
                    flags,
                    parser_depth
                    );

                dbgTrace(D_WAAP_DEEP_PARSER) << " rc = " << rc;
                if (rc != CONTINUE_PARSING) {
                    return rc;
                }
            }
            break;
        case CONTINUE_AS_IS:
            break;
        default:
            break;
    }

    if (base64ParamFound) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): pushing #base64 prefix to the key.";
        m_key.push("#base64", 7, false);
    }

    // cur_val is later passed through some filters (such as urldecode) before JSON, XML or HTML is detected/decoded
    std::string orig_val = cur_val;

    // Escape HTML entities such as &nbsp; before running heuristic stats analyzer
    std::string cur_val_html_escaped = orig_val;
    cur_val_html_escaped.erase(
        escape_html(cur_val_html_escaped.begin(), cur_val_html_escaped.end()), cur_val_html_escaped.end()
    );

    // Calculate various statistics over currently processed value
    ValueStatsAnalyzer valueStats(cur_val_html_escaped);
    dbgTrace(D_WAAP_DEEP_PARSER) << "ValueStats:\n " << valueStats.textual;

    if (valueStats.canSplitPipe || valueStats.canSplitSemicolon) {
        std::string key = IndicatorsFiltersManager::generateKey(m_key.first(), m_key.str(), m_pTransaction);
        m_pWaapAssetState->m_filtersMngr->pushSample(key, cur_val, m_pTransaction);
    }

    // Detect and decode UTF-16 data
    Waap::Util::decodeUtf16Value(valueStats, cur_val);

    // First buffer in stream
    int offset;
    if (flags & BUFFERED_RECEIVER_F_FIRST) {
        offset = createInternalParser(
            k,
            k_len,
            orig_val,
            valueStats,
            isBodyPayload,
            isRefererPayload,
            isRefererParamPayload,
            isUrlPayload,
            isUrlParamPayload,
            flags,
            parser_depth
        );
    } else {
        offset = 0;
    }

    if (isDebugRequired(TRACE, D_WAAP_STREAMING_PARSING)) {
        printParserDeque();
    }
    dbgTrace(D_WAAP_STREAMING_PARSING)
        << "\n\toffset = "
        << offset
        << "\n\tm_parsersDeque.empty() = "
        << m_parsersDeque.empty()
        << "\n\tm_parsersDeque.size() = "
        << m_parsersDeque.size()
        << "\n\tparser_depth = "
        << parser_depth << "\n\tdepth = "
        << m_depth;
    // defends on parsers' queue for case when ParserRaw created from Waf2Transaction and not placed to m_parsersDeque
    if (!m_parsersDeque.empty()) {
        dbgTrace(D_WAAP_STREAMING_PARSING) << "m_parsersDeque.size() = " << m_parsersDeque.size();
        if (m_parsersDeque.size() > parser_depth) {
            dbgTrace(D_WAAP_STREAMING_PARSING)
                << "m_parsersDeque.at(parser_depth-1)->getRecursionFlag() = "
                << m_parsersDeque.at(parser_depth)->getRecursionFlag();
        }
    }

    // If there's a parser in parsers stack, push the value to the top parser
    if (!m_parsersDeque.empty()
        && offset >= 0
        && m_parsersDeque.size() > parser_depth
        &&!m_parsersDeque.at(parser_depth)->getRecursionFlag()
        ) {
        ScopedContext ctx;
        ctx.registerValue<IWaf2Transaction *>("waap_transaction", m_pTransaction);
        rc = pushValueToTopParser(cur_val, flags, base64ParamFound, offset, parser_depth);
        if (rc != CONTINUE_PARSING) {
            if (shouldUpdateKeyStack) {
                m_key.pop("deep parser key");
            }


            m_depth--;
            return rc;
        }
    }


    if (rc == CONTINUE_PARSING) {
        // Try  to eliminate m_multipart_boundary  to allow other parser to work instead of multipart
        if (m_depth == 1
            && isBodyPayload
            && !m_multipart_boundary.empty()
            && !Waap::Util::testUrlBareUtf8Evasion(cur_val)
            && !valueStats.hasSpace
            && valueStats.hasCharAmpersand
            && valueStats.hasTwoCharsEqual
            && !isBinaryData()
            ) {
            m_multipart_boundary = "";
            rc = parseAfterMisleadingMultipartBoundaryCleaned(
                k,
                k_len,
                orig_val,
                valueStats,
                isBodyPayload,
                isRefererPayload,
                isRefererParamPayload,
                isUrlPayload,
                isUrlParamPayload,
                flags,
                parser_depth,
                base64ParamFound
                );
            if (rc != CONTINUE_PARSING) {
                return rc;
            }
        }
    }
    dbgTrace(D_WAAP_DEEP_PARSER)
        << "rc = "
        << rc;

    // Parse buffer
    // Note: API report does not include output of "PIPE" and similar extracted stuff.
    // However, it does include output of URLEncode, MIME, JSON, XML, HTML ...
    // Also, do not report API for data collected from headers (including the cookie header)
    if (m_splitRefs == 0 && !isHeaderPayload && !isRefererPayload && !isRefererParamPayload && !isUrlPayload &&
        !isCookiePayload) {
        // A bit ugly (need to rethink/refactor!): remove #.base64 temporarily while adding entry to API report.
        if (base64ParamFound) {
            dbgTrace(D_WAAP_DEEP_PARSER)
                << "DeepParser::onKv(): temporarily removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        apiProcessKey(v, v_len);

        // A bit ugly: add back #.base64 after adding entry to API report, so it is reported
        // correctly if WAF suspicion found...
        if (base64ParamFound) {
            dbgTrace(D_WAAP_DEEP_PARSER)
                << "DeepParser::onKv(): returning temporarily removed #base64 prefix to the key.";
            m_key.push("#base64", 7, false);
        }
    }

    if (isUrlPayload) {
        valueStats.canSplitPipe = false;
        valueStats.canSplitSemicolon = false;
    }
    rc = parseBuffer(valueStats, orig_val, base64ParamFound, shouldUpdateKeyStack, parser_depth);
    if (rc != CONTINUE_PARSING) {
        return rc;
    }

    if (Waap::Util::detectJSONasParameter(cur_val, decoded_key, decoded_val)) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << " detectJSONasParameter was  true: key = "
            << decoded_key
            << " value = "
            << decoded_val;

        rc = onKv(
            decoded_key.c_str(),
            decoded_key.size(),
            decoded_val.data(),
            decoded_val.size(),
            flags,
            parser_depth
            );

        dbgTrace(D_WAAP_DEEP_PARSER) << " After processing potential JSON rc = " << rc;
        if (rc != CONTINUE_PARSING) {
            return rc;
        }
    }

    m_depth--;

    // Send key/value pair to the Signature scanner

    if (m_key.size() > 0 || cur_val.size() > 0) {
        if (m_deepParserFlag) {
            rc = m_receiver.onKv(
                m_key.c_str(),
                strlen(m_key.c_str()),
                cur_val.data(),
                cur_val.size(),
                flags,
                parser_depth
            );
        } else {
            rc = m_receiver.onKv(k, k_len, cur_val.data(), cur_val.size(), flags, parser_depth);
        }
    }

    if (base64ParamFound) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
        m_key.pop("#base64", false);
    }

    if (shouldUpdateKeyStack) {
        m_key.pop("deep parser key");
    }
    return rc;
}

int
DeepParser::parseBuffer(
    ValueStatsAnalyzer &valueStats,
    const std::string &cur_val,
    bool base64ParamFound,
    bool shouldUpdateKeyStack,
    size_t parser_depth
)
{
    dbgFlow(D_WAAP_DEEP_PARSER) << "cur_val='" << cur_val << "'";
    // TODO: SplitRegex should be replaced by streaming solution, probably, ParserDelimiter in this case
    // detect and decode stuff like "a=b;c=d;e=f;klm"
    if (valueStats.canSplitSemicolon && valueStats.hasCharSemicolon && cur_val.length() > 0 &&
        splitByRegex(cur_val, m_pWaapAssetState->getSignatures()->semicolon_split_re, "sem", parser_depth)) {
        if (base64ParamFound) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }

        m_depth--;
        return DONE_PARSING;
    }
    // TODO: SplitRegex should be replaced by streaming solution, probably, ParserDelimiter in this case
    // detect and decode stuff like "abc|def|klm"
    if (valueStats.canSplitPipe && valueStats.hasCharPipe && cur_val.length() > 0 &&
        splitByRegex(cur_val, m_pWaapAssetState->getSignatures()->pipe_split_re, "pipe", parser_depth)) {
        // split done - do not send the unsplit string to the scanner

        if (base64ParamFound) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return DONE_PARSING;
    }

    return CONTINUE_PARSING;
}

int
DeepParser::pushValueToTopParser(
    std::string &cur_val,
    int flags,
    bool base64ParamFound,
    int offset,
    size_t parser_depth
)
{
    std::shared_ptr<ParserBase> actualParser = m_parsersDeque.at(parser_depth);
    dbgTrace(D_WAAP_STREAMING_PARSING)
        << "Actual parser name = "
        << actualParser->name()
        << " \tparser_depth="
        << parser_depth
        << " \tName by parser depth = "
        << m_parsersDeque.at(parser_depth)->name()
        << " \toffset = "
        << offset
        << " \tflags = "
        << flags;

    if (isDebugRequired(TRACE, D_WAAP_STREAMING_PARSING)) {
        printParserDeque();
    }

    if (!actualParser->error()) {
        m_deepParserFlag = true;
        m_parsersDeque.at(parser_depth)->setRecursionFlag();

        // Push current buffer to the top parser
        // This might generate one or more recursive calls back to DeepParser::onKv()
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::pushValueToTopParser():"
            << cur_val.size()
            << " bytes parser "
            << actualParser->name();
        actualParser->push(cur_val.c_str() + offset, cur_val.length() - offset);

        // Last buffer in stream
        if (flags & BUFFERED_RECEIVER_F_LAST) {
            actualParser->finish();
        }

        m_parsersDeque.at(parser_depth)->clearRecursionFlag();
        m_deepParserFlag = false;
    } else {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::pushValueToTopParser():"
            << cur_val.size()
            << " bytes to parser "
            << actualParser->name()
            << " (parser is in error state)";
    }

    // TODO - must ensure that its removal correct!!!!!
    // Last buffer in stream
    if (!m_parsersDeque.empty() && flags & BUFFERED_RECEIVER_F_LAST) {
        // Remove the top parser from the stack
        m_parsersDeque.pop_back();
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::pushValueToTopParser(): "
            << " Remove the top parser from the stack"
            << " parser_depth = "
            << parser_depth
            << " flags = "
            << flags;
    }

    if (base64ParamFound) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): temporarily removing the #base64 prefix from the key.";
        m_key.pop("#base64", false);
    }

    if (!actualParser->error()) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::pushValueToTopParser(): parser "
            << actualParser->name()
            << " is still valid on depth = "
            << parser_depth
            << "DeepParser::pushValueToTopParser(): "
            << "   return DONE_PARSING";
        return DONE_PARSING; // do not send the parsed source to the scanner
    }
    dbgTrace(D_WAAP_DEEP_PARSER)
        << "DeepParser::pushValueToTopParser(): "
        << "   return CONTINUE_PARSING";
    return CONTINUE_PARSING;
}

class StubParserReceiver : public IParserReceiver
{
    int
    onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth)
    {
        return 0;
    }
};

static bool
checkIfdelimeteredPattern(const std::string &pattern, char delim)
{
    bool is_empty = true;
    bool has_eq_sign = false;
    for (auto &ch : pattern) {
        if (ch == '=') has_eq_sign = true;
        is_empty = false;
        if (ch == delim) {
            if (!has_eq_sign) return false;
            is_empty = true;
            has_eq_sign = false;
        }
    }
    return has_eq_sign || is_empty;
}

static bool
validateJson(const char *v, size_t v_len)
{
    StubParserReceiver rcvr;
    ParserJson jsParser(rcvr);
    jsParser.push(v, v_len);
    dbgTrace(D_WAAP_DEEP_PARSER) << "json validation: " << (jsParser.error() ? "invalid" : "valid");
    return !jsParser.error();
}

void
DeepParser::printParserDeque()
{
    if (isDebugRequired(TRACE, D_WAAP_STREAMING_PARSING)) {
        dbgTrace(D_WAAP_STREAMING_PARSING) << "---- Printing parser queue: -----";
        for (auto it = m_parsersDeque.begin(); it != m_parsersDeque.end(); ++it) {
            std::shared_ptr<ParserBase> tmp = *it;
            dbgTrace(D_WAAP_STREAMING_PARSING) << "\t\t" << tmp->name();
        }
        dbgTrace(D_WAAP_STREAMING_PARSING) << "---- End of parsers queue -----";
    }
}

// getShiftInUrlEncodedBuffer receives potential encoded URL and calculates offset where URL query is starting
// i.e. in case of input like "http[s]://domain[:port]/uri_path?param=value&..." offset will point to
// 1st character of  of query i.e. "param=value&..."
// In case input doesn't comply URI format, negative value will be returned
// This function also supports old notation where semicolon used instead of ampersand
int
DeepParser::getShiftInUrlEncodedBuffer(const ValueStatsAnalyzer &valueStats, std::string &cur_val)
{
    dbgTrace(D_WAAP_DEEP_PARSER) << "getShiftInUrlEncodedBuffer(): " << cur_val;
    bool continue_flag = false;
    int offset = -1;
    const char *end = cur_val.c_str() + cur_val.size();
    const char *p = cur_val.c_str();

    if (valueStats.hasCharSlash && valueStats.hasCharEqual && cur_val.length() > 1 && cur_val[0] == '/') {
        p++;
        continue_flag = true;
        offset = 1;

        // Read path part until it either hits '?' or '/'
        while (p < end && (isalpha(*p) || isdigit(*p) || *p == '.' || *p == '-' || *p == '_')) {
            p++;
            offset++;
        }
    }

    if (offset < 0)  p = cur_val.c_str();
    if (valueStats.hasCharColon && valueStats.hasCharSlash && cur_val.length() > 7) {
        if (*p++ == 'h' && *p++ == 't' && *p++ == 't' && *p++ == 'p') {
            // value starts with "http"
            offset = 4;
            if (*p == 's') {
                // starts with "https"
                p++;
                offset++;
            }

            if (*p++ == ':' && *p++ == '/' && *p++ == '/') {
                // cur_val starts with "http://" or "https://"
                // first, ensure that domain name is valid (to eliminate false detections of URLs)
                // added '@' and ':' to comply format domain name in URL (user_context@domain.name:port_num)
                offset +=3;
                while (
                    p < end
                    && (isalpha(*p) || isdigit(*p) || *p == '.' || *p == '-' || *p == '_' || *p == ':' || *p == '@')
                    ) {
                    p++;
                    offset++;
                }
                if (*p != '/') return -1;
                continue_flag = true;
            }
        }
    }

    if (continue_flag) {
        // domain name is seemingly valid, and we hit '/' character
        // skip the path to find the '?' character
        // in contradiction to canonical definition allowed chars ';' in the path of URL to avoid some false positives
        p = strchr(p, '?');
        const char *start_point = cur_val.c_str();

        if (p) {
            int range = cur_val.length();
            int shift = p - start_point;
            // Value starts as url, and contains '?' character: urldecode the rest.
            if (shift < range) {
                offset = shift;
                if (*p == '?')  offset++;
            }
        } else {
            offset = -1;
        }
    }  else {
        offset = -1;
    }
    return offset;
}
int
DeepParser::parseAfterMisleadingMultipartBoundaryCleaned(
    const char *k,
    size_t k_len,
    std::string &cur_val,
    const ValueStatsAnalyzer &valueStats,
    bool isBodyPayload,
    bool isRefererPayload,
    bool isRefererParamPayload,
    bool isUrlPayload,
    bool isUrlParamPayload,
    int flags,
    size_t parser_depth,
    bool base64ParamFound)
{
    int offset = -1;
    int rc = 0;
    bool shouldUpdateKeyStack = (flags & BUFFERED_RECEIVER_F_UNNAMED) == 0;
    if (flags & BUFFERED_RECEIVER_F_FIRST) {
        offset = createInternalParser(
            k,
            k_len,
            cur_val,
            valueStats,
            isBodyPayload,
            isRefererPayload,
            isRefererParamPayload,
            isUrlPayload,
            isUrlParamPayload,
            flags,
            parser_depth
        );
    } else {
        offset = 0;
    }

    if (isDebugRequired(TRACE, D_WAAP_STREAMING_PARSING)) {
        printParserDeque();
    }

    dbgTrace(D_WAAP_STREAMING_PARSING)
        << "\n\toffset = "
        << offset
        << "\n\tm_parsersDeque.empty() = "
        << m_parsersDeque.empty()
        << "\n\tm_parsersDeque.size() = "
        << m_parsersDeque.size()
        << "\n\tparser_depth = "
        << parser_depth << "\n\tdepth = "
        << m_depth;
    // defends on parsers' queue for case when ParserRaw created from Waf2Transaction and not placed to m_parsersDeque
    if (!m_parsersDeque.empty()) {
        dbgTrace(D_WAAP_STREAMING_PARSING) << "\n\tm_parsersDeque.size() = " << m_parsersDeque.size();
        if (m_parsersDeque.size() > parser_depth) {
            dbgTrace(D_WAAP_STREAMING_PARSING)
                << "m_parsersDeque.at(parser_depth-1)->getRecursionFlag() = "
                << m_parsersDeque.at(parser_depth)->getRecursionFlag();
        }
    }

    // If there's a parser in parsers stack, push the value to the actual parser
    if (!m_parsersDeque.empty()
        && offset >= 0
        && m_parsersDeque.size() > parser_depth
        &&!m_parsersDeque.at(parser_depth)->getRecursionFlag()
    ) {
        ScopedContext ctx;
        ctx.registerValue<IWaf2Transaction *>("waap_transaction", m_pTransaction);
        rc = pushValueToTopParser(cur_val, flags, base64ParamFound, offset, parser_depth);
        if (rc != CONTINUE_PARSING) {
            if (shouldUpdateKeyStack) {
                m_key.pop("deep parser key");
            }


            m_depth--;
            return rc;
        }
    }


    return rc;
}

static bool err = false;
static const SingleRegex json_detector_re("\\A[{\\[][^;\",}\\]]*[,:\"].+[\\s\\S]", err, "json_detector");
static const SingleRegex json_quoteless_detector_re("^[{\\[][[,0-9nul\\]]+", err, "json_quoteless_detector");

//intended to keep and process all types of leftovers detected as separate cases for parsing
int
DeepParser::createUrlParserForJson(
const char *k,
size_t k_len,
std::string &cur_val,
const ValueStatsAnalyzer &valueStats,
bool isBodyPayload,
bool isRefererPayload,
bool isRefererParamPayload,
bool isUrlPayload,
bool isUrlParamPayload,
int flags,
size_t parser_depth
) {
    int ret_val = -1;
    std::string decoded_key, decoded_val;
    dbgTrace(D_WAAP_DEEP_PARSER)
        << "Last try create parsers for value: >>>"
        << cur_val
        << "\n\tm_parsersDeque.size() = "
        << m_parsersDeque.size()
        << "\n\tparser_depth = "
        << parser_depth
        << "\n\tdepth = "
        << m_depth
        << "\n\tflags: "
        << flags
        << "\n\tparser_depth: "
        << parser_depth;

    if (Waap::Util::detectJSONasParameter(cur_val, decoded_key, decoded_val)) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "Detected param=JSON,"
            << " still starting to parse an Url-encoded-like data due to possible tail";
        m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserPairs>>(*this, parser_depth + 1));
        ret_val = 0;
    }
    return ret_val;
}


int
DeepParser::createInternalParser(
    const char *k,
    size_t k_len,
    std::string &cur_val,
    const ValueStatsAnalyzer &valueStats,
    bool isBodyPayload,
    bool isRefererPayload,
    bool isRefererParamPayload,
    bool isUrlPayload,
    bool isUrlParamPayload,
    int flags,
    size_t parser_depth
)
{
    dbgTrace(D_WAAP_DEEP_PARSER)
        << "Starting create parsers for value: >>>"
        << cur_val
        << "<<<\n\tm_parsersDeque.empty() = "
        << m_parsersDeque.empty()
        << "\n\tm_parsersDeque.size() = "
        << m_parsersDeque.size()
        << "\n\tparser_depth = "
        << parser_depth
        << "\n\tdepth = "
        << m_depth
        << "\n\tflags: "
        << flags
        << "\n\tparser_depth: "
        << parser_depth;
    bool isPipesType = false, isSemicolonType = false, isAsteriskType = false, isCommaType = false,
        isAmperType = false;
    bool isKeyValDelimited = false;
    bool isHtmlType = false;
    bool isBinaryType = false;
    int offset = -1;
    auto pWaapAssetState = m_pTransaction->getAssetState();
    std::shared_ptr<Signatures> signatures = m_pWaapAssetState->getSignatures();
    if (pWaapAssetState != nullptr) {
        // Find out learned type
        std::set<std::string> paramTypes = pWaapAssetState->m_filtersMngr->getParameterTypes(
            IndicatorsFiltersManager::generateKey(m_key.first(), m_key.str(), m_pTransaction)
        );

        dbgTrace(D_WAAP_DEEP_PARSER) << "ParamTypes (count=" << paramTypes.size() << "):";
        for (const auto &paramType : paramTypes) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "ParamType: '" << paramType << "'";
        }

        if (!paramTypes.empty()) {
            std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
            boost::smatch match;
            if (paramTypes.find("ampersand_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = checkIfdelimeteredPattern(cur_val, '&');
                isAmperType = sampleType.find("ampersand_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("pipes") != paramTypes.end())
            {
                isKeyValDelimited = checkIfdelimeteredPattern(cur_val, '|');
                isPipesType = sampleType.find("pipes") != sampleType.end();
            }
            else if (paramTypes.find("semicolon_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = checkIfdelimeteredPattern(cur_val, ';');
                isSemicolonType = sampleType.find("semicolon_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("asterisk_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = checkIfdelimeteredPattern(cur_val, '*');
                isAsteriskType = sampleType.find("asterisk_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("comma_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = checkIfdelimeteredPattern(cur_val, ',');
                isCommaType = sampleType.find("comma_delimiter") != sampleType.end();
            }

            if (paramTypes.find("html_input") != paramTypes.end()) {
                std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
                if (sampleType.find("html_input") != sampleType.end()) {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "html_input sample type learned and validated";
                    isHtmlType = true;
                }
            }

            if (paramTypes.find("binary_input") != paramTypes.end()) {
                std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
                if (sampleType.find("binary_input") != sampleType.end()) {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "binary_input sample type learned and validated";
                    isBinaryType = true;
                }
            }
        }
    }

    // Detect wbxml (binary XML) data type
    if (m_depth == 1 && isBodyPayload && !valueStats.isUTF16 && m_pWaapAssetState->isWBXMLSampleType(cur_val)) {
        m_is_wbxml = true;
        dbgTrace(D_WAAP_DEEP_PARSER) << "WBXML data type detected";
    }

    // This flag is enabled when current value is either top level (depth==1), or one-level inside multipart-encoded
    // container (depth==2 and type of top parser is "ParserMultipartForm")
    bool isTopData = m_depth == 1
        || (m_depth == 2 && !m_parsersDeque.empty() && m_parsersDeque.front()->name() == "ParserMultipartForm");

    // GQL query can potentially be in one of three places in HTTP request:
    // 1. In url parameter named "query"
    // 2. In the body when Content-Type is "application/graphql"
    // 3. In the JSON contained in body, where top-level JSON parameter is named "query"
    // Note: we consider decoding Graphql format only if it is contained whole within the MAX_VALUE_SIZE (64k) buffer
    // size (you can find the value of MAX_VALUE_SIZE defined in ParserBase.cc).
    Waap::Util::ContentType requestContentType = m_pTransaction->getContentType();
    bool isPotentialGqlQuery = false;

    if (flags == BUFFERED_RECEIVER_F_BOTH) { // TODO:: should we limit ourselves to the 64k buffer?
        static std::string strQuery("query");
        bool isParamQuery = strQuery.size() == k_len && std::equal(k, k + k_len, strQuery.begin());
        isPotentialGqlQuery |= isParamQuery
            && m_depth == 1
            && (isUrlParamPayload || isRefererParamPayload);
        isPotentialGqlQuery |= m_depth == 1
            && isBodyPayload
            && requestContentType == Waap::Util::CONTENT_TYPE_GQL;
        isPotentialGqlQuery |= isParamQuery
            && m_depth == 2
            && isBodyPayload
            && requestContentType == Waap::Util::CONTENT_TYPE_JSON;
    }
    dbgTrace(D_WAAP_DEEP_PARSER)
        << "\n\tm_parsersDeque.empty() = "
        << m_parsersDeque.empty()
        << "\n\tm_parsersDeque.size() = "
        << m_parsersDeque.size()
        << "\n\tparser_depth = "
        << parser_depth
        << "\n\tdepth = "
        << m_depth;
    if (parser_depth > 0) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "isPotentialGqlQuery="
            << isPotentialGqlQuery
            << ";isTopData="
            << isTopData
            << ";depth="
            << m_depth
            << (m_parsersDeque.empty() ? "" : ";actualParserName=" + m_parsersDeque.at(parser_depth - 1)->name());
    }

    // Add zero or one parser on top of the parsers stack
    // Note that this function must not add more than one parser
    // because only the topmost parser will run on the value.
    // Normally, DeepParser will take care of recursively run other parsers.

    if (isHtmlType
        && !isRefererPayload
        && !isUrlPayload
        ) {
        // HTML detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an HTML file";
        m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserHTML>>(*this, parser_depth + 1));
        offset = 0;
    } else if (cur_val.size() > 0 && signatures->php_serialize_identifier.hasMatch(cur_val)) {
        // PHP value detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse phpSerializedData";
        m_parsersDeque.push_back(std::make_shared<BufferedParser<PHPSerializedDataParser>>(*this, parser_depth + 1));
        offset = 0;
    } else if (isPotentialGqlQuery
        && cur_val.size() > 0
        && !validateJson(cur_val.data(), cur_val.size())
        ) {
        // Graphql value detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse graphql";
        m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserGql>>(*this, parser_depth + 1));
        offset = 0;
    } else if (cur_val.length() > 0
        && (cur_val[0] == '[' || cur_val[0] == '{')
        ) {
        boost::smatch confulence_match;
        dbgTrace(D_WAAP_DEEP_PARSER) << "attempt to find confluence of JSON by '{' or '['";
        if (NGEN::Regex::regexMatch(__FILE__, __LINE__, cur_val, confulence_match, signatures->confluence_macro_re)) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a confluence macro";
            m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserConfluence>>(*this, parser_depth + 1));
            offset = 0;
        } else {
            dbgTrace(D_WAAP_DEEP_PARSER) << "attempt to find JSON by '{' or '['";
            bool percent_encoded_doublequote_detected = cur_val.find("%22") != std::string::npos;
            if (json_detector_re.hasMatch(cur_val)
                && (valueStats.hasDoubleQuote
                    || json_quoteless_detector_re.hasMatch(cur_val)
                    || percent_encoded_doublequote_detected)) {
                // JSON value detected
                if (percent_encoded_doublequote_detected && !valueStats.hasDoubleQuote) {
                    // We have JSOn but it %-encoded, first start percent decoding for it. Very narrow case
                    dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a JSON file from percent decoding";
                    m_parsersDeque.push_back(
                        std::make_shared<BufferedParser<ParserPercentEncode>>(*this, parser_depth + 1)
                    );
                    offset = 0;
                } else {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a JSON file";
                    // Send openApiReceiver as secondary receiver,
                    // but only if the JSON is passed in body and on the top level.
                    bool should_collect_for_oa_schema_updater = false;

                    m_parsersDeque.push_back(
                        std::make_shared<BufferedParser<ParserJson>>(
                            *this,
                            should_collect_for_oa_schema_updater,
                            parser_depth + 1
));
                    offset = 0;
                }
            }
        }
    }
    if (offset < 0) {
        if (cur_val.length() > 4
            && (cur_val[0] == '<')
            && !isRefererPayload
            && !isRefererParamPayload
            && !isUrlPayload
            && !isUrlParamPayload
            && !startsWithHtmlTagName(cur_val.c_str() + 1)
            ) {
            // XML detected. Note: XML must be at a minimum 4 bytes long to be valid.
            // Also, XML is not scanned in payload coming from URL or URL parameters, or if the
            // payload starts with one of known HTML tags.
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an XML file";
            m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserXML>>(*this, parser_depth + 1));
            offset = 0;
        } else if (m_depth == 1 && isBodyPayload && !m_multipart_boundary.empty()) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a multipart file";
            m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserMultipartForm>>(
                *this, parser_depth + 1, m_multipart_boundary.c_str(), m_multipart_boundary.length()
            ));
            offset = 0;
        } else if (isTopData && (isBinaryType || m_pWaapAssetState->isBinarySampleType(cur_val))) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a binary file";
            m_parsersDeque.push_back(std::make_shared<BufferedParser<ParserBinary>>(*this, parser_depth + 1));
            offset = 0;
        }
    }
    if (offset < 0) {
        if (isPipesType) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse pipes, positional: " << isKeyValDelimited;
            if (isKeyValDelimited) {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(*this, parser_depth + 1, '|')
                );
                offset = 0;
            } else {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserDelimiter>>(*this, parser_depth + 1, '|', "pipe")
                );
                offset = 0;
            }
        } else if (isSemicolonType) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a semicolon, positional: " << isKeyValDelimited;
            if (isKeyValDelimited) {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(*this, parser_depth + 1, ';')
                );
                offset = 0;
            } else {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserDelimiter>>(*this, parser_depth + 1, ';', "sem")
                );
                offset = 0;
            }
        } else if (isAsteriskType) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an asterisk, positional: " << isKeyValDelimited;
            if (isKeyValDelimited) {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(*this, parser_depth + 1, '*')
                );
                offset = 0;
            } else {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserDelimiter>>(*this, parser_depth + 1, '*', "asterisk")
                );
                offset = 0;
            }
        } else if (isCommaType) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a comma, positional: " << isKeyValDelimited;
            if (isKeyValDelimited) {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(*this, parser_depth + 1, ',')
                );
                offset = 0;
            } else {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserDelimiter>>(*this, parser_depth + 1, ',', "comma")
                );
                offset = 0;
            }
        } else if (isAmperType) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a ampersand, positional: " << isKeyValDelimited;
            if (isKeyValDelimited) {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(*this, parser_depth + 1, '&')
                );
                offset = 0;
            } else {
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserDelimiter>>(*this, parser_depth + 1, '&', "amp")
                );
                offset = 0;
            }
        // the following block is added to allow streaming parsing (instead of unstreamed parser usage from
        // DeepParser::parseBuffer - code was removed from there
        // In case we have some kind of URI (with or without protocol/port), getShiftInUrlEncodedBuffer method will
        // detect where URI path is started and based on this ParserUrlEncode parser will be created for sub-buffer
        // else ParserPercentEncode parser is invoked
        } else if (
            valueStats.hasCharSlash
            && (valueStats.hasCharColon || valueStats.hasCharEqual)
            && !valueStats.hasCharLess
            ) {
            offset = getShiftInUrlEncodedBuffer(valueStats, cur_val);
            dbgTrace(D_WAAP_DEEP_PARSER)
                << "offset = "
                << offset
                << " cur_val.size = "
                << cur_val.size()
                << " cur_val.len = "
                << cur_val.length();
            int delta = offset - cur_val.size();
            if (offset >= 0 && delta <= 0) {
                dbgTrace(D_WAAP_DEEP_PARSER) << " Starting to parse an Url-encoded data after removing prefix";
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(
                        *this,
                        parser_depth + 1,
                        '&',
                        valueStats.isUrlEncoded)
                );
            } else if (!Waap::Util::testUrlBareUtf8Evasion(cur_val)) {
                dbgTrace(D_WAAP_DEEP_PARSER) << "!Waap::Util::testUrlBareUtf8Evasion(cur_val)";
                if (!valueStats.hasSpace
                    && valueStats.hasCharAmpersand
                    && valueStats.hasTwoCharsEqual
                    && !isBinaryData()
                ) {
                    dbgTrace(D_WAAP_DEEP_PARSER) << " Starting to parse an Url-encoded data - pairs detected";
                    m_parsersDeque.push_back(
                        std::make_shared<BufferedParser<ParserUrlEncode>>(
                            *this,
                            parser_depth + 1,
                            '&',
                            valueStats.isUrlEncoded)
                    );
                    offset = 0;
                    return offset;
                } else if (valueStats.isUrlEncoded && !Waap::Util::testUrlBadUtf8Evasion(cur_val)) {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an percent decoding";
                    m_parsersDeque.push_back(
                        std::make_shared<BufferedParser<ParserPercentEncode>>(*this, parser_depth + 1)
                    );
                    offset = 0;
                    return offset;
                }
            }
        } else if (!Waap::Util::testUrlBareUtf8Evasion(cur_val)) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "!Waap::Util::testUrlBareUtf8Evasion(cur_val)";
            if (!valueStats.hasSpace
                && valueStats.hasCharAmpersand
                && valueStats.hasTwoCharsEqual
                && !isBinaryData()
            ) {
                dbgTrace(D_WAAP_DEEP_PARSER) << " Starting to parse an Url-encoded data - pairs detected";
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserUrlEncode>>(
                        *this,
                        parser_depth + 1,
                        '&',
                        valueStats.isUrlEncoded)
                );
                offset = 0;
                return offset;
            } else if (valueStats.isUrlEncoded && !Waap::Util::testUrlBadUtf8Evasion(cur_val)) {
                dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an percent decoding";
                m_parsersDeque.push_back(
                    std::make_shared<BufferedParser<ParserPercentEncode>>(*this, parser_depth + 1)
                );
                offset = 0;
                return offset;
            }
        }
    }
    if (offset < 0) {
        offset = createUrlParserForJson(
            k,
            k_len,
            cur_val,
            valueStats,
            isBodyPayload,
            isRefererPayload,
            isRefererParamPayload,
            isUrlPayload,
            isUrlParamPayload,
            flags,
            parser_depth
            );
    }
    return offset;
}


void
DeepParser::apiProcessKey(const char *v, size_t v_len)
{
    // Build dot-formatted full keyword name
    std::string kwType = m_key.first();
    std::string kwFullName = m_key.str();

    if (v_len == 0 && kwFullName.size() == 0) {
        return;
    }

    m_keywordInfo.push_back(KeywordInfo(kwType, kwFullName, v, v_len));
}

// TODO:: maybe convert this splitter to Parser-derived class?
bool
DeepParser::splitByRegex(const std::string &val, const Regex &r, const char *keyPrefix, size_t parser_depth)
{
    bool splitDone = false;
    std::vector<RegexMatch> matches;
    r.findAllMatches(val, matches);

    dbgTrace(D_WAAP_DEEP_PARSER)
        << "DeepParser::splitByRegex(): splitting '"
        << val << "' keyPrefix='"
        << keyPrefix
        << "' into "
        << matches.size()
        << "u pieces ...";

    size_t splitIndex = 0;
    for (size_t i = 0; i < matches.size(); ++i) {
        for (size_t j = 0; j < matches[i].groups.size(); ++j) {
            RegexMatch::MatchGroup &g = matches[i].groups[j];
            char nbuf[64];
            snprintf(nbuf, sizeof(nbuf), "%s", keyPrefix);
            dbgTrace(D_WAAP_DEEP_PARSER)
                << "DeepParser::splitByRegex(): split part '"
                << nbuf
                << "'='"
                << g.value.c_str()
                << "'";
            // re-scan each part, recursively
            // TODO:: check exit code of onKv() call?

            // Refcount recursive entries into "split" subparsers.
            // Any content that is result of "split" won't be included in API structured report.
            Ref ref(m_splitRefs);
            // Remember most recent split type and its exact parsing depth
            m_splitTypesStack.push(std::make_tuple(m_depth, splitIndex++, std::string(keyPrefix)));
            if (!g.value.empty()) {
                // Send non-empty split parts to deeper scanning
                onKv(
                    nbuf,
                    strlen(nbuf),
                    g.value.data(),
                    g.value.size(),
                    BUFFERED_RECEIVER_F_BOTH,
                    parser_depth
                    );
            }
            // Forget most recent split type
            m_splitTypesStack.pop();
            splitDone = true;
        }
    }

    dbgTrace(D_WAAP_DEEP_PARSER)
        << "DeepParser::splitByRegex(): end splitting '"
        << keyPrefix
        << "' (split done: "
        << (splitDone ? "YES" : "NO")
        << ") ...";
    return splitDone;
}

void
DeepParser::setMultipartBoundary(const std::string &boundary)
{
    m_multipart_boundary = boundary;
}

const std::string &
DeepParser::getMultipartBoundary() const
{
    return m_multipart_boundary;
}

bool
DeepParser::isBinaryData() const
{
    for (const auto &parser : m_parsersDeque) {
        if (parser->name() == "binary") return true;
    }
    return false;
}

const std::string
DeepParser::getActualParser(size_t parser_depth) const
{
    if (m_parsersDeque.empty()) {
        return "";
    } else {
        return m_parsersDeque.at(parser_depth)->name();
    }
}

bool
DeepParser::isWBXmlData() const
{
    return m_is_wbxml;
}

Maybe<std::string>
DeepParser::getSplitType() const
{
    dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: enter. current m_depth=" << m_depth;
    if (!m_splitTypesStack.empty()) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "getSplitType: stack top: (depth="
            << std::get<0>(m_splitTypesStack.top())
            << ", splitIndex="
            << std::get<1>(m_splitTypesStack.top())
            << ", splitType='"
            << std::get<2>(m_splitTypesStack.top())
            << "')";
    } else {
        dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: stack is empty";
    }

    // Return only immediate split type. Ignore additional levels of parsers inside splitted item, and ignore
    // any first item in the splitted value (ex. "id;ls" -> "id" is first item in split list and hence ignored)
    if (m_splitTypesStack.empty()
        || std::get<0>(m_splitTypesStack.top()) != m_depth
        || std::get<1>(m_splitTypesStack.top()) == 0
            ) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: returning empty string";
        return genError("should not be split");
    }
    return std::get<2>(m_splitTypesStack.top());
}

bool
DeepParser::isGlobalMaxObjectDepthReached() const
{
    return m_globalMaxObjectDepthReached;
}

bool
DeepParser::shouldEnforceDepthLimit(const std::shared_ptr<ParserBase> &parser) const
{
    const std::string &name = parser->name();
    if ((name == ParserJson::m_parserName) || (name == ParserXML::m_parserName)) {
        return true;
    }
    return false;
}
