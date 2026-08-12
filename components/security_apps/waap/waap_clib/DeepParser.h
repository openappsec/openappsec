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

#ifndef __PARSER_PARAMETER_DEEP_H__549cc3ee
#define __PARSER_PARAMETER_DEEP_H__549cc3ee

#include "ParserBase.h"
#include "KeyStack.h"
#include "WaapAssetState.h"
#include "Waf2Regex.h"
#include "Waf2Util.h"
#include "WaapDedicatedParsers.h"
#include "maybe_res.h"
#include <deque>

// Deep (recursively) parses/dissects parameters based on input stream
class DeepParser : public IParserReceiver
{
public:
    DeepParser(std::shared_ptr<WaapAssetState> pWaapAssetState, IParserReceiver &receiver,
        IWaf2Transaction* pTransaction);
    virtual ~DeepParser();
    void setWaapAssetState(std::shared_ptr<WaapAssetState> pWaapAssetState);
    // This callback receives input key/value pairs, dissects, decodes and deep-scans these, recursively
    // finally, it calls onDetected() on each detected parameter.
    virtual int onKv(const char *k, size_t k_len, const char *v, size_t v_len, int flags, size_t parser_depth);

    void clear();
    // Initialize per-request context caches (dedicated parsers policy pointer, URI, method).
    // Must be called from start_request_body() after the site config is fully resolved.
    void initRequestContext();
    // Returns true when dedicated parser rules are active for the current request.
    // Used by tests and can also inform debug/logging at higher levels.
    bool hasDedicatedParsers() const { return m_cachedDedicatedParsersPolicy != nullptr; }
    void showStats(std::string& buff, const ValueStatsAnalyzer& valueStats);
    void apiProcessKey(const char *v, size_t v_len);
    size_t depth() const;
    void setGlobalMaxObjectDepth(size_t depth) { m_globalMaxObjectDepth = depth; }
    size_t getGlobalMaxObjectDepth() const { return m_globalMaxObjectDepth; }
    bool isGlobalMaxObjectDepthReached() const;
    size_t getLocalMaxObjectDepth() const { return m_localMaxObjectDepth; }
    void setMultipartBoundary(const std::string &boundary);
    const std::string &getMultipartBoundary() const;
    bool isBinaryData() const;
    const std::string getActualParser(size_t parser_depth) const;
    bool isWBXmlData() const;
    Maybe<std::string> getSplitType() const;
    std::vector<std::pair<std::string, std::string> > kv_pairs;

    // Represents information stored per-keyword
    struct KeywordInfo
    {
        std::string type;
        std::string name;
        std::string val;
        KeywordInfo() {}

        KeywordInfo(
            const std::string &type,
            const std::string &name,
            const char *v,
            size_t v_len) :
                type(type),
                name(name),
                val(std::string(v, v_len))
        {
        }

        size_t getLength() const
        {
            return val.size();
        }

        const std::string &getName() const
        {
            return name;
        }

        const std::string &getType() const
        {
            return type;
        }

        // Return the value itself
        const std::string &getValue() const
        {
            return val;
        }
    };

    // KeywordInfo maintained for each keyword name
    std::vector<KeywordInfo> m_keywordInfo;

    KeyStack m_key;
    int getShiftInUrlEncodedBuffer(const ValueStatsAnalyzer &valueStats, std::string &cur_val);

private:
    class Ref
    {
    public:
        Ref(int &ref):m_ref(ref) { m_ref++; }
        ~Ref() { m_ref--; }
    private:
        int &m_ref;
    };

    std::shared_ptr<WaapAssetState> m_pWaapAssetState;
    IWaf2Transaction* m_pTransaction;
    IParserReceiver &m_receiver;
    size_t m_depth;
    int m_splitRefs;    // incremented when entering recursion due to "split" action,
                        // decremented afterwards. If >0, apiProcessKey should not be called.

    // Split a value by given regexp. Return true if split, false otherwise.
    // note: This function calls onKv(), and the call can be recursive!
    // TODO:: maybe convert this splitter to Parser-derived class?!
    bool splitByRegex(const std::string &val, const Regex &r, const char *keyPrefix, size_t parser_depth);

    int createInternalParser(
        const char *k,
        size_t k_len,
        std::string &cur_val,
        const ValueStatsAnalyzer &valueStats,
        bool isBodyPayload,
        bool isRefererPayload,
        bool isRefererParamPayload,
        bool isUrlPayload,
        bool isUrlParamPayload,
        bool isCookiePayload,
        const std::string &locationLabel,
        int flags,
        size_t parser_depth,
        Waap::Util::BinaryFileType b64FileType,
        bool b64DataEncoded = false
    );

    int createUrlParserForJson(
        const char *k,
        size_t k_len,
        std::string &cur_val,
        const ValueStatsAnalyzer &valueStats,
        bool isBodyPayload,
        bool isRefererPayload,
        bool isRefererParamPayload,
        bool isUrlPayload,
        bool isUrlParamPayload,
        bool isCookiePayload,
        int flags,
        size_t parser_depth
    );

    void printParserDeque();

    int parseAfterMisleadingMultipartBoundaryCleaned(
        const char *k,
        size_t k_len,
        std::string &cur_val,
        const ValueStatsAnalyzer &valueStats,
        bool isBodyPayload,
        bool isRefererPayload,
        bool isRefererParamPayload,
        bool isUrlPayload,
        bool isUrlParamPayload,
        bool isCookiePayload,
        const std::string &locationLabel,
        int flags,
        size_t parser_depth,
        bool base64ParamFound,
        Waap::Util::BinaryFileType b64FileType
    );
    int pushValueToTopParser(std::string &cur_val, int flags, bool base64ParamFound, int offset, size_t parser_depth);
    int parseBuffer(
        ValueStatsAnalyzer &valueStats,
        const std::string &cur_val,
        bool base64ParamFound,
        bool shouldUpdateKeyStack,
        size_t parser_depth
    );
    bool shouldEnforceDepthLimit(const std::shared_ptr<ParserBase>& parser) const;
    void setLocalMaxObjectDepth(size_t depth) { m_localMaxObjectDepth = depth; }
    void setGlobalMaxObjectDepthReached() { m_globalMaxObjectDepthReached = true; }
    bool isPDFDetected(const std::string &cur_val) const;

    // Check if a dedicated parser is configured for the current parameter context
    // Returns the parser type if found, or genError if not configured
    Maybe<Waap::DedicatedParsers::ParserType> getDedicatedParserType(
        const std::string& paramName,
        const std::string& location) const;

    // Create a parser based on the dedicated parser type
    // Returns offset (0) if parser was created, -1 if not applicable
    int createDedicatedParser(
        Waap::DedicatedParsers::ParserType parserType,
        size_t parser_depth);

    bool m_deepParserFlag;
    std::stack<std::tuple<size_t, size_t, std::string>> m_splitTypesStack; // depth, splitIndex, splitType
    std::deque<std::shared_ptr<ParserBase>> m_parsersDeque;
    std::string m_multipart_boundary;
    size_t m_globalMaxObjectDepth;
    size_t m_localMaxObjectDepth;
    bool m_globalMaxObjectDepthReached;
    bool m_is_wbxml;

    // Per-request cache set by initRequestContext() at the start of each request body.
    // Non-null only when dedicated parser rules are active; used as the fast early-exit
    // guard inside createInternalParser() (one pointer comparison, no virtual calls).
    // URI and method are read lazily from m_pTransaction only when this is non-null.
    // Raw ptr into the shared_ptr owned by the site config - valid for the lifetime of one request.
    const Waap::DedicatedParsers::DedicatedParsersConfig* m_cachedDedicatedParsersPolicy;
};

#endif // __PARSER_PARAMETER_DEEP_H__549cc3ee
