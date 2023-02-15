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
#include "ParserDelimiter.h"
#include "WaapAssetState.h"
#include "Waf2Regex.h"
#include "Waf2Util.h"
#include "debug.h"
#include "i_transaction.h"
#include "agent_core_utilities.h"

USE_DEBUG_FLAG(D_WAAP_DEEP_PARSER);
USE_DEBUG_FLAG(D_WAAP_ULIMITS);

#define DONE_PARSING 0
#define FAILED_PARSING -1
#define CONTINUE_PARSING 1
#define MAX_DEPTH 7

DeepParser::DeepParser(
    std::shared_ptr<WaapAssetState> pWaapAssetState,
    IParserReceiver& receiver,
    IWaf2Transaction* pTransaction)
:
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
{
}

DeepParser::~DeepParser()
{
}


void DeepParser::setWaapAssetState(std::shared_ptr<WaapAssetState> pWaapAssetState)
{
    m_pWaapAssetState = pWaapAssetState;
}

void DeepParser::clear()
{
    m_depth = 0;
    m_splitRefs = 0;
    kv_pairs.clear();
    m_key.clear();
    kv_pairs.clear();
    m_keywordInfo.clear();
    m_multipart_boundary = "";
}

size_t DeepParser::depth() const
{
    return m_depth;
}

// Called when another key/value pair is ready
int DeepParser::onKv(const char* k, size_t k_len, const char* v, size_t v_len, int flags)
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
        << flags;

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
        rc = m_receiver.onKv(m_key.c_str(), strlen(m_key.c_str()), cur_val.data(), cur_val.size(), flags);
        m_depth--;
        return rc;
    }

    size_t currDepth = 0;
    if (!isGlobalMaxObjectDepthReached()) {
        for (const auto& parser : m_parsersDeque) {
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
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] DeepParser::onKv(): Object depth limit exceeded " <<
            currDepth << "/" << getGlobalMaxObjectDepth() <<
            " no. of parsers: " << m_parsersDeque.size();
        return DONE_PARSING;
    }
    else {
        dbgTrace(D_WAAP_ULIMITS) << "[USER LIMITS] DeepParser::onKv(): current object depth " <<
            currDepth << "/" << getGlobalMaxObjectDepth() <<
            " no. of parsers: " << m_parsersDeque.size();
    }

    // Ignore when both key and value are empty
    if (k_len == 0 && v_len == 0)
    {
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
    if( m_depth == 1 && isCookiePayload &&
        (m_key.str() == "x-chkp-csrf-token" || m_key.str() == "__fn1522082288")) {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): found: "
            << m_key.str()
            << "cookie - sending to Waf2Transaction to collect cookie value.";
        rc = m_receiver.onKv(m_key.c_str(), strlen(m_key.c_str()), cur_val.data(), cur_val.size(), flags);
        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return rc;
    }

    // If csrf header - send to Waf2Transaction for collection of cookie value.
    if( m_depth == 1 && isHeaderPayload && m_key.str() == "x-chkp-csrf-token") {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): found csrf header - sending to Waf2Transaction to collect cookie value.";
        rc = m_receiver.onKv(m_key.c_str(), strlen(m_key.c_str()), cur_val.data(), cur_val.size(), flags);
        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;
        return rc;
    }

    // If csrf body - send to Waf2Transaction for collection of cookie value.
    if(isBodyPayload && m_key.str() == "x-chkp-csrf-token") {
        std::string cur_val = std::string(v, v_len);
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): found csrf form data - sending to Waf2Transaction to collect cookie value.";
        rc = m_receiver.onKv(m_key.c_str(), strlen(m_key.c_str()), cur_val.data(), cur_val.size(), flags);
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
        if ((k_len > 0 || v_len > 0) &&
            !isHeaderPayload &&
            !isUrlPayload &&
            !isRefererPayload &&
            !isRefererParamPayload &&
            !isCookiePayload) {
            dbgTrace(D_WAAP_DEEP_PARSER) << " kv_pairs.push_back";
            kv_pairs.push_back(std::make_pair(std::string(k, k_len), std::string(v, v_len)));
        }
    }

    // TODO:: do we need to construct std::string for this in this function??
    std::string cur_val = std::string(v, v_len);

    // Detect and decode potential base64 chunks in the value before further processing

    bool base64ParamFound = false;
    dbgTrace(D_WAAP_DEEP_PARSER) << " ===Processing potential base64===";
    std::string decoded_val, key;
    base64_variants base64_status = Waap::Util::b64Test (cur_val,
            key,
            decoded_val);

    dbgTrace(D_WAAP_DEEP_PARSER)
        << " status = "
        << base64_status
        << " key = "
        << key
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
            rc = onKv(key.c_str(), key.size(), cur_val.data(), cur_val.size(), flags);
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
    cur_val_html_escaped.erase(escape_html(cur_val_html_escaped.begin(), cur_val_html_escaped.end()),
        cur_val_html_escaped.end());

    // Calculate various statistics over currently processed value
    ValueStatsAnalyzer valueStats(cur_val_html_escaped);

    if (valueStats.isUrlEncoded && !Waap::Util::testUrlBareUtf8Evasion(cur_val) &&
            !Waap::Util::testUrlBadUtf8Evasion(cur_val)) {
        Waap::Util::decodePercentEncoding(cur_val);
    }

    if (valueStats.canSplitPipe || valueStats.canSplitSemicolon)
    {
        std::string key = IndicatorsFiltersManager::generateKey(m_key.first(), m_key.str(), m_pTransaction);
        m_pWaapAssetState->m_filtersMngr->pushSample(key, cur_val, m_pTransaction);
    }

    // Detect and decode UTF-16 data
    Waap::Util::decodeUtf16Value(valueStats, cur_val);

    // First buffer in stream

    if (flags & BUFFERED_RECEIVER_F_FIRST)
    {
        createInternalParser(k, k_len, orig_val,
            valueStats,
            isBodyPayload,
            isRefererPayload,
            isRefererParamPayload,
            isUrlPayload,
            isUrlParamPayload,
            flags);
    }

    // If there's a parser in parsers stack, push the value to the top parser
    if (!m_parsersDeque.empty() && !m_parsersDeque.front()->getRecursionFlag())
    {
        ScopedContext ctx;
        ctx.registerValue<IWaf2Transaction*>("waap_transaction", m_pTransaction);
        rc = pushValueToTopParser(cur_val, flags, base64ParamFound);
        if (rc != CONTINUE_PARSING)
        {
            if (shouldUpdateKeyStack) {
                m_key.pop("deep parser key");
            }
            m_depth--;
            return rc;
        }
    }


    // Parse buffer

    // Note: API report does not include output of "PIPE" and similar extracted stuff.
    // However, it does include output of URLEncode, MIME, JSON, XML, HTML ...
    // Also, do not report API for data collected from headers (including the cookie header)
    if (m_splitRefs == 0 &&
        !isHeaderPayload &&
        !isRefererPayload &&
        !isRefererParamPayload &&
        !isUrlPayload &&
        !isCookiePayload) {
        // A bit ugly (need to rethink/refactor!): remove #.base64 temporarily while adding entry to API report.
        if (base64ParamFound)
        {
            dbgTrace(D_WAAP_DEEP_PARSER)
                << "DeepParser::onKv(): temporarily removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        apiProcessKey(v, v_len);

        // A bit ugly: add back #.base64 after adding entry to API report, so it is reported
        // correctly if WAF suspicion found...
        if (base64ParamFound)
        {
            dbgTrace(D_WAAP_DEEP_PARSER) <<
                "DeepParser::onKv(): returning temporarily removed #base64 prefix to the key.";
            m_key.push("#base64", 7, false);
        }
    }

    if (isUrlPayload)
    {
        valueStats.canSplitPipe = false;
        valueStats.canSplitSemicolon = false;
    }
    rc = parseBuffer(valueStats, orig_val, base64ParamFound, shouldUpdateKeyStack);
    if (rc != CONTINUE_PARSING)
    {
        return rc;
    }

    if (Waap::Util::detectJSONasParameter(cur_val, key, decoded_val)) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << " detectJSONasParameter was  true: key = "
            << key
            << " value = "
            << decoded_val;

        rc = onKv(key.c_str(), key.size(), decoded_val.data(), decoded_val.size(), flags);

        dbgTrace(D_WAAP_DEEP_PARSER) << " After processing potential JSON rc = " << rc;
        if (rc != CONTINUE_PARSING) {
            return rc;
        }
    }

    m_depth--;

    // Send key/value pair to the Signature scanner

    if (m_key.size() > 0 || cur_val.size() > 0)
    {
        if (m_deepParserFlag)
        {
            rc = m_receiver.onKv(m_key.c_str(), strlen(m_key.c_str()), cur_val.data(), cur_val.size(), flags);
        }
        else
        {
            rc = m_receiver.onKv(k, k_len, cur_val.data(), cur_val.size(), flags);
        }
    }

    if (base64ParamFound)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
        m_key.pop("#base64", false);
    }

    if (shouldUpdateKeyStack) {
        m_key.pop("deep parser key");
    }
    return rc;
}


int DeepParser::parseBuffer(ValueStatsAnalyzer& valueStats, const std::string& cur_val, bool base64ParamFound,
    bool shouldUpdateKeyStack)
{
    dbgFlow(D_WAAP_DEEP_PARSER) << "cur_val='" << cur_val << "'";

    // Detect and decode stuff in relative urls like /a.php?blah=cow&...
    // TODO:: when removing cur_val -> PAY ATTENTION THAT THIS CODE ASSUMES
    // cur_val is ZERO TERMINATED STRING!
    if (valueStats.hasCharSlash && valueStats.hasCharEqual && cur_val.length() > 1 && cur_val[0] == '/')
    {
        const char* p = cur_val.c_str() + 1;
        // Read path part until it either hits '?' or '/'
        while (isalpha(*p) || isdigit(*p) || *p == '.' || *p == '-' || *p == '_')
        {
            p++;
        }

        if (*p == '?' || *p == '/')
        {
            if (*p == '?')
            {
                // '?' character is found
                p++;
            }
            else
            {
                // Path seem to be starting correctly, hitting the '/' character.
                // Skip the path to find the '?' character
                p = strchr(p, '?');
                if (p) {
                    // '?' character is found
                    p++;
                }
            }

            if (p)
            {
                // Value starts as url, and contains '?' character: urldecode the rest.
                dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): relative url -> parsing urlencode";
                // Avoid using any output of this and deeper subparsers for API structure report.
                Ref ref(m_splitRefs);
                BufferedReceiver rcvr(*this);
                size_t buff_len = cur_val.length() - (p - &cur_val[0]);
                ParserUrlEncode up(rcvr, '&', checkUrlEncoded(p, buff_len));
                up.push(p, buff_len);
                up.finish();

                if (base64ParamFound)
                {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
                    m_key.pop("#base64", false);
                }

                if (shouldUpdateKeyStack) {
                    m_key.pop("deep parser key");
                }
                m_depth--;

                if (!up.error())
                {
                    return DONE_PARSING;
                }
            }
            else
            {
                return CONTINUE_PARSING;
            }
        }
    }

    // Detect and decode stuff like URLs that start with http:// or https://
    if (valueStats.hasCharColon && valueStats.hasCharSlash && cur_val.length() > 7)
    {
        const char* p = cur_val.c_str();

        if (*p++ == 'h' && *p++ == 't' && *p++ == 't' && *p++ == 'p')
        {
            // value starts with "http"
            if (*p == 's')
            {
                // starts with "https"
                p++;
            }

            if (*p++ == ':' && *p++ == '/' && *p++ == '/')
            {
                // cur_val starts with "http://" or "https://"
                // first, ensure that domain name is valid (to eliminate false detections of URLs)
                while (isalpha(*p) || isdigit(*p) || *p == '.' || *p == '-' || *p == '_')
                {
                    p++;
                }

                if (*p == '/')
                {
                    // domain name is seemingly valid, and we hit '/' character
                    p++;
                    // skip the path to find the '?' character
                    p = strchr(p, '?');

                    if (p)
                    {
                        // Value starts as url, and contains '?' character: urldecode the rest.
                        p++;

                        // Avoid using any output of this and deeper subparsers for API structure report.
                        Ref ref(m_splitRefs);

                        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): full url -> parsing urlencode";
                        BufferedReceiver rcvr(*this);
                        size_t buff_len = cur_val.length() - (p - &cur_val[0]);
                        ParserUrlEncode up(rcvr, '&', checkUrlEncoded(p, buff_len));
                        up.push(p, buff_len);
                        up.finish();

                        if (base64ParamFound)
                        {
                            dbgTrace(D_WAAP_DEEP_PARSER)
                                << "DeepParser::onKv(): removing the #base64 prefix from the key.";
                            m_key.pop("#base64", false);
                        }

                        if (shouldUpdateKeyStack) {
                            m_key.pop("deep parser key");
                        }
                        m_depth--;

                        if (!up.error())
                        {
                            return DONE_PARSING;
                        }
                    }
                    else
                    {
                        return CONTINUE_PARSING;
                    }
                }
            }
        }
    }

    bool isUrlBareUtf8Evasion = valueStats.isUrlEncoded && Waap::Util::testUrlBareUtf8Evasion(cur_val);

    bool isUrlBadUtf8Evasion = valueStats.isUrlEncoded && Waap::Util::testUrlBadUtf8Evasion(cur_val);

    bool isUrlEncodedPairs = valueStats.hasCharAmpersand && valueStats.hasTwoCharsEqual;

    if (valueStats.isUrlEncoded && !isUrlEncodedPairs && !isUrlBareUtf8Evasion && !isUrlBadUtf8Evasion) {
        // Single UrlEncoded (percent-encoded) value detected, not urlencoded pairs
        dbgTrace(D_WAAP_DEEP_PARSER) <<
            "DeepParser::onKv(): urlencoded single value detected, decoding percent encoding";
        std::string decodedVal = cur_val;
        Waap::Util::decodePercentEncoding(decodedVal, true);
        onKv("", 0, decodedVal.data(), decodedVal.size(), BUFFERED_RECEIVER_F_BOTH | BUFFERED_RECEIVER_F_UNNAMED);

        if (base64ParamFound)
        {
            dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;

        return DONE_PARSING;
    }
    else if (!valueStats.hasSpace && isUrlEncodedPairs && !isUrlBareUtf8Evasion && !isBinaryData())
    {
        // If there are 1 or more '&' characters, or 2 or more '=' characters - assume its
        // URLEncoded data and apply URL decode to the value.
        // This case applies even to samples like "a=b&c=d" where no percent-encoding is present.
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): urlencoded pairs value detected, parsing urlencode pairs";
        // Avoid using any output of this and deeper subparsers for API structure report.
        Ref ref(m_splitRefs);
        BufferedReceiver rcvr(*this);
        ParserUrlEncode up(rcvr, '&', checkUrlEncoded(cur_val.data(), cur_val.size()));
        up.push(cur_val.data(), cur_val.size());
        up.finish();

        if (base64ParamFound)
        {
            dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): removing the #base64 prefix from the key.";
            m_key.pop("#base64", false);
        }

        if (shouldUpdateKeyStack) {
            m_key.pop("deep parser key");
        }
        m_depth--;

        if (!up.error())
        {
            return DONE_PARSING;
        }
    }
    // detect and decode stuff like "a=b;c=d;e=f;klm"
    if (valueStats.canSplitSemicolon &&
        (valueStats.hasCharSemicolon) &&
        cur_val.length() > 0 &&
        splitByRegex(cur_val, m_pWaapAssetState->getSignatures()->semicolon_split_re, "sem"))
    {
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

    // detect and decode stuff like "abc|def|klm"
    if (valueStats.canSplitPipe &&
        (valueStats.hasCharPipe) &&
        cur_val.length() > 0 &&
        splitByRegex(cur_val, m_pWaapAssetState->getSignatures()->pipe_split_re, "pipe"))
    {
        // split done - do not send the unsplit string to the scanner

        if (base64ParamFound)
        {
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

int DeepParser::pushValueToTopParser(std::string& cur_val, int flags, bool base64ParamFound)
{
    std::shared_ptr<ParserBase> topParser = m_parsersDeque.front();

    if (!topParser->error())
    {
        m_deepParserFlag = true;
        m_parsersDeque.front()->setRecursionFlag();

        // Push current buffer to the top parser
        // This might generate one or more recursive calls back to DeepParser::onKv()
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): push "
            << cur_val.size()
            << " bytes parser "
            << topParser->name();
        topParser->push(cur_val.c_str(), cur_val.length());

        // Last buffer in stream
        if (flags & BUFFERED_RECEIVER_F_LAST)
        {
            // Tell the top parser that the stream is finished
            // This might still generate one or more recursive calls back to DeepParser::onKv()
            topParser->finish();
        }

        m_parsersDeque.front()->clearRecursionFlag();
        m_deepParserFlag = false;
    }
    else
    {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "DeepParser::onKv(): skip push "
            << cur_val.size()
            << " bytes to parser "
            << topParser->name()
            << " (parser is in error state)";
    }

    // Last buffer in stream
    if (!m_parsersDeque.empty() && flags & BUFFERED_RECEIVER_F_LAST)
    {
        // Remove the top parser from the stack
        m_parsersDeque.pop_front();
    }

    if (base64ParamFound)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): temporarily removing the #base64 prefix from the key.";
        m_key.pop("#base64", false);
    }

    if (!topParser->error())
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "DeepParser::onKv(): parser " << topParser->name() << " is still valid.";
        return DONE_PARSING; // do not send the parsed source to the scanner
    }

    return CONTINUE_PARSING;
}

class StubParserReceiver : public IParserReceiver {
    int
    onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags)
    {
        return 0;
    }
};

static bool
validateJson(const char *v, size_t v_len)
{
    StubParserReceiver rcvr;
    ParserJson jsParser(rcvr);
    jsParser.push(v, v_len);
    dbgTrace(D_WAAP_DEEP_PARSER) << "json validation: " << (jsParser.error() ? "invalid" : "valid");
    return !jsParser.error();
}

void DeepParser::createInternalParser(const char *k, size_t k_len, std::string& cur_val,
    const ValueStatsAnalyzer &valueStats,
    bool isBodyPayload,
    bool isRefererPayload,
    bool isRefererParamPayload,
    bool isUrlPayload,
    bool isUrlParamPayload,
    int flags)
{
    bool isPipesType = false, isSemicolonType = false, isAsteriskType = false,
        isCommaType = false, isAmperType = false;
    bool isKeyValDelimited = false;
    bool isHtmlType = false;
    bool isBinaryType = false;
    auto pWaapAssetState = m_pTransaction->getAssetState();
    std::shared_ptr<Signatures> signatures = m_pWaapAssetState->getSignatures();
    if (pWaapAssetState != nullptr)
    {
        // Find out learned type
        std::set<std::string> paramTypes = pWaapAssetState->m_filtersMngr->getParameterTypes(
            IndicatorsFiltersManager::generateKey(m_key.first(), m_key.str(), m_pTransaction));

        dbgTrace(D_WAAP_DEEP_PARSER) << "ParamTypes (count=" << paramTypes.size() << "):";
        for (const auto &paramType : paramTypes) {
            dbgTrace(D_WAAP_DEEP_PARSER) << "ParamType: '" << paramType << "'";
        }

        if (!paramTypes.empty())
        {
            std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
            boost::smatch match;
            if (paramTypes.find("ampersand_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = NGEN::Regex::regexMatch(
                    __FILE__,
                    __LINE__,
                    cur_val,
                    match,
                    signatures->ampersand_delimited_key_val_re
                );
                isAmperType = sampleType.find("ampersand_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("pipes") != paramTypes.end())
            {
                isKeyValDelimited = NGEN::Regex::regexMatch(
                    __FILE__,
                    __LINE__,
                    cur_val,
                    match,
                    signatures->pipes_delimited_key_val_re
                );
                isPipesType = sampleType.find("pipes") != sampleType.end();
            }
            else if (paramTypes.find("semicolon_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = NGEN::Regex::regexMatch(
                    __FILE__,
                    __LINE__,
                    cur_val,
                    match,
                    signatures->semicolon_delimited_key_val_re
                );
                isSemicolonType = sampleType.find("semicolon_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("asterisk_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = NGEN::Regex::regexMatch(
                    __FILE__,
                    __LINE__,
                    cur_val,
                    match,
                    signatures->asterisk_delimited_key_val_re
                );
                isAsteriskType = sampleType.find("asterisk_delimiter") != sampleType.end();
            }
            else if (paramTypes.find("comma_delimiter") != paramTypes.end())
            {
                isKeyValDelimited = NGEN::Regex::regexMatch(
                    __FILE__,
                    __LINE__,
                    cur_val,
                    match,
                    signatures->comma_delimited_key_val_re
                );
                isCommaType = sampleType.find("comma_delimiter") != sampleType.end();
            }

            if (paramTypes.find("html_input") != paramTypes.end())
            {
                std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
                if (sampleType.find("html_input") != sampleType.end())
                {
                    dbgTrace(D_WAAP_DEEP_PARSER) << "html_input sample type learned and validated";
                    isHtmlType = true;
                }
            }

            if (paramTypes.find("binary_input") != paramTypes.end())
            {
                std::set<std::string> sampleType = m_pWaapAssetState->getSampleType(cur_val);
                if (sampleType.find("binary_input") != sampleType.end())
                {
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
        isPotentialGqlQuery |= isParamQuery && m_depth == 1 && (isUrlParamPayload || isRefererParamPayload);
        isPotentialGqlQuery |= m_depth == 1 && isBodyPayload && requestContentType == Waap::Util::CONTENT_TYPE_GQL;
        isPotentialGqlQuery |= isParamQuery && m_depth == 2 && isBodyPayload &&
            requestContentType == Waap::Util::CONTENT_TYPE_JSON;
    }

    dbgTrace(D_WAAP_DEEP_PARSER)
        << "isPotentialGqlQuery="
        << isPotentialGqlQuery
        << ";isTopData="
        << isTopData
        << ";depth="
        << m_depth
        << (m_parsersDeque.empty() ? "" : ";topParserName=" + m_parsersDeque.front()->name());

    // Add zero or one parser on top of the parsers stack
    // Note that this function must not add more than one parser
    // because only the topmost parser will run on the value.
    // Normally, DeepParser will take care of recursively run other parsers.
    if (isHtmlType &&
        !isRefererPayload &&
        !isUrlPayload)
    {
        // HTML detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an HTML file";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserHTML>>(*this));
    }
    else if (cur_val.size() > 0 && signatures->php_serialize_identifier.hasMatch(cur_val))
    {
        // PHP value detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse phpSerializedData";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<PHPSerializedDataParser>>(*this));
    }
    else if (isPotentialGqlQuery && cur_val.size() > 0 && !validateJson(cur_val.data(), cur_val.size())) {
        // Graphql value detected
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse graphql";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserGql>>(*this));
    }
    else if (cur_val.length() > 0 && (cur_val[0] == '[' || cur_val[0] == '{'))
    {
        boost::smatch confulence_match;

        if (NGEN::Regex::regexMatch(__FILE__, __LINE__, cur_val, confulence_match, signatures->confluence_macro_re))
        {
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a confluence macro";
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserConfluence>>(*this));
        }
        else
        {
            // JSON value detected
            dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a JSON file";
            // Send openApiReceiver as secondary receiver, but only if the JSON is passed in body and on the top level.


            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserJson>>(*this));
        }
    }
    else if (cur_val.length() > 4 &&
        (cur_val[0] == '<') &&
        !isRefererPayload &&
        !isRefererParamPayload &&
        !isUrlPayload &&
        !isUrlParamPayload &&
        !startsWithHtmlTagName(cur_val.c_str() + 1))
    {
        // XML detected. Note: XML must be at a minimum 4 bytes long to be valid.
        // Also, XML is not scanned in payload coming from URL or URL parameters, or if the
        // payload starts with one of known HTML tags.
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an XML file";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserXML>>(*this));
    }
    else if (m_depth == 1 &&
        isBodyPayload &&
        !m_multipart_boundary.empty()) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a multipart file";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserMultipartForm>>(
            *this,
            m_multipart_boundary.c_str(),
            m_multipart_boundary.length()
            ));
    }
    else if (isTopData && (isBinaryType || m_pWaapAssetState->isBinarySampleType(cur_val)))
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a binary file";
        m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserBinary>>(*this));
    }
    else if (isPipesType) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse pipes, positional: " << isKeyValDelimited;
        if (isKeyValDelimited)
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserUrlEncode>>(*this, '|'));
        }
        else
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserDelimiter>>(*this, '|', "pipe"));
        }
    }
    else if (isSemicolonType)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a semicolon, positional: " << isKeyValDelimited;
        if (isKeyValDelimited)
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserUrlEncode>>(*this, ';'));
        }
        else
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserDelimiter>>(*this, ';', "sem"));
        }
    }
    else if (isAsteriskType)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse an asterisk, positional: " << isKeyValDelimited;
        if (isKeyValDelimited)
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserUrlEncode>>(*this, '*'));
        }
        else
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserDelimiter>>(*this, '*', "asterisk"));
        }
    }
    else if (isCommaType)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a comma, positional: " << isKeyValDelimited;
        if (isKeyValDelimited)
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserUrlEncode>>(*this, ','));
        }
        else
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserDelimiter>>(*this, ',', "comma"));
        }
    }
    else if (isAmperType)
    {
        dbgTrace(D_WAAP_DEEP_PARSER) << "Starting to parse a ampersand, positional: " << isKeyValDelimited;
        if (isKeyValDelimited)
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserUrlEncode>>(*this, '&'));
        }
        else
        {
            m_parsersDeque.push_front(std::make_shared<BufferedParser<ParserDelimiter>>(*this, '&', "amp"));
        }
    }
}

void DeepParser::apiProcessKey(const char* v, size_t v_len)
{
    // Build dot-formatted full keyword name
    std::string kwType = m_key.first();
    std::string kwFullName = m_key.str();

    if (v_len == 0 && kwFullName.size() == 0)
    {
        return;
    }

    m_keywordInfo.push_back(KeywordInfo(kwType, kwFullName, v, v_len));
}

// TODO:: maybe convert this splitter to Parser-derived class?
bool DeepParser::splitByRegex(const std::string& val, const Regex& r, const char* keyPrefix)
{
    bool splitDone = false;
    std::vector<RegexMatch> matches;
    r.findAllMatches(val, matches);

    dbgTrace(D_WAAP_DEEP_PARSER)
        << "DeepParser::splitByRegex(): splitting '"
        << val
        << "' keyPrefix='"
        << keyPrefix
        << "' into "
        << matches.size()
        << "u pieces ...";

    size_t splitIndex = 0;
    for (size_t i = 0; i < matches.size(); ++i)
    {
        for (size_t j = 0; j < matches[i].groups.size(); ++j)
        {
            RegexMatch::MatchGroup& g = matches[i].groups[j];
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
                onKv(nbuf, strlen(nbuf), g.value.data(), g.value.size(), BUFFERED_RECEIVER_F_BOTH);
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

void DeepParser::setMultipartBoundary(const std::string &boundary)
{
    m_multipart_boundary = boundary;
}

const std::string &DeepParser::getMultipartBoundary() const
{
    return m_multipart_boundary;
}

bool DeepParser::isBinaryData() const
{
    for (const auto &parser : m_parsersDeque) {
        if (parser->name() == "binary") return true;
    }
    return false;
}

const std::string DeepParser::getLastParser() const
{
    if (m_parsersDeque.empty()) {
        return "";
    }
    else {
        return m_parsersDeque.front()->name();
    }
}

bool DeepParser::isWBXmlData() const
{
    return m_is_wbxml;
}

Maybe<std::string> DeepParser::getSplitType() const
{
    dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: enter. current m_depth=" << m_depth;
    if (!m_splitTypesStack.empty()) {
        dbgTrace(D_WAAP_DEEP_PARSER)
            << "getSplitType: stack top: (depth=" << std::get<0>(m_splitTypesStack.top())
            << ", splitIndex=" << std::get<1>(m_splitTypesStack.top())
            << ", splitType='" << std::get<2>(m_splitTypesStack.top())
            << "')";
    }
    else {
        dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: stack is empty";
    }

    // Return only immediate split type. Ignore additional levels of parsers inside splitted item, and ignore
    // any first item in the splitted value (ex. "id;ls" -> "id" is first item in split list and hence ignored)
    if (
        m_splitTypesStack.empty() ||
        std::get<0>(m_splitTypesStack.top()) != m_depth ||
        std::get<1>(m_splitTypesStack.top()) == 0
    ) {
        dbgTrace(D_WAAP_DEEP_PARSER) << "getSplitType: returning empty string";
        return genError("should not be split");
    }
    return std::get<2>(m_splitTypesStack.top());
}

bool DeepParser::isGlobalMaxObjectDepthReached() const
{
    return m_globalMaxObjectDepthReached;
}

bool DeepParser::shouldEnforceDepthLimit(const std::shared_ptr<ParserBase>& parser) const
{
    const std::string& name = parser->name();
    if ((name == ParserJson::m_parserName) ||
        (name == ParserXML::m_parserName)) {
        return true;
    }
    return false;
}
