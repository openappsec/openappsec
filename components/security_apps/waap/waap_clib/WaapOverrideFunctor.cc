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

#include <string>
#include <cctype>
#include <boost/regex.hpp>
#include "WaapOverrideFunctor.h"
#include "Waf2Engine.h"
#include "CidrMatch.h"
#include "RegexComparator.h"
#include "agent_core_utilities.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_OVERRIDE);

#define REGX_MATCH(FIELD_FETCH) \
    NGEN::Regex::regexMatch(__FILE__, __LINE__, FIELD_FETCH.c_str(), what, *rx)
#define W2T_REGX_MATCH(FIELD_GETTER) \
    REGX_MATCH(waf2Transaction.FIELD_GETTER())

WaapOverrideFunctor::WaapOverrideFunctor(Waf2Transaction& waf2Transaction) :waf2Transaction(waf2Transaction)
{
}

bool WaapOverrideFunctor::operator()(const std::string& tag, const std::vector<Waap::Util::CIDRData> &values) {
    std::string sourceIp;
    if (tag == "sourceip") {
        dbgDebug(D_WAAP_OVERRIDE)
            << "Remote IP Address : "
            << waf2Transaction.getRemoteAddr();

        sourceIp = waf2Transaction.getRemoteAddr();
    } else if (tag == "sourceidentifier") {
        dbgDebug(D_WAAP_OVERRIDE) << "Remote IP Address : " << waf2Transaction.getRemoteAddr();
        sourceIp = waf2Transaction.getSourceIdentifier();
    } else {
        dbgWarning(D_WAAP_OVERRIDE) << "Unsupported tag: " << tag;
        return false;
    }

    Waap::Util::CIDRData source_cidr;
    if (!Waap::Util::isCIDR(sourceIp, source_cidr)) {
        dbgWarning(D_WAAP_OVERRIDE) << "Failed to create subnet from: " << sourceIp;
        return false;
    }


    int left = 0;
    int right = values.size() - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (Waap::Util::cidrMatch(sourceIp, values[mid])) return true;

        if (values[mid] < source_cidr) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return false;
}

bool WaapOverrideFunctor::operator()(
    const std::string &tag,
    const std::set<std::shared_ptr<boost::regex>, Waap::Util::RegexComparator> &rxes)
{
    boost::cmatch what;
    std::string tagLower = tag;
    std::transform(tagLower.begin(), tagLower.end(), tagLower.begin(), ::tolower);

    try {
        if (tagLower == "method") {
            for (const auto &rx : rxes) {
                if (W2T_REGX_MATCH(getMethod)) return true;
            }
            return false;
        }
        else if (tagLower == "url") {
            for (const auto &rx : rxes) {
                if (W2T_REGX_MATCH(getUriStr)) return true;
            }
            return false;
        }
        else if (tagLower == "hostname") {
            for (const auto &rx : rxes) {
                if (W2T_REGX_MATCH(getHost)) return true;
            }
            return false;
        }
        else if (tagLower == "sourceidentifier") {
            for (const auto &rx : rxes) {
                if (W2T_REGX_MATCH(getSourceIdentifier)) return true;
            }
            return false;
        }
        else if (tagLower == "keyword") {
            for (const auto &rx : rxes) {
                for (const std::string& keywordStr : waf2Transaction.getKeywordMatches()) {
                    if (REGX_MATCH(keywordStr)) {
                        return true;
                    }
                }
            }
            return false;
        }
        else if (tagLower == "paramname") {
            for (const auto &rx : rxes) {
                for (const DeepParser::KeywordInfo& keywordInfo : waf2Transaction.getKeywordInfo()) {
                    if (REGX_MATCH(keywordInfo.getName())) {
                        return true;
                    }
                }
                if (W2T_REGX_MATCH(getParamKey)) return true;
                if (W2T_REGX_MATCH(getParam)) return true;
            }
            return false;
        }
        else if (tagLower == "paramvalue") {
            for (const auto &rx : rxes) {
                for (const DeepParser::KeywordInfo& keywordInfo : waf2Transaction.getKeywordInfo()) {
                    if (REGX_MATCH(keywordInfo.getValue())) {
                        return true;
                    }
                }
                if (W2T_REGX_MATCH(getSample)) return true;
            }

            return false;
        }
        else if (tagLower == "paramlocation") {
            for (const auto &rx : rxes) {
                if (W2T_REGX_MATCH(getLocation)) return true;
            }
            return false;
        }
        else if (tagLower == "responsebody") {
            waf2Transaction.getResponseInspectReasons().setApplyOverride(true);
            if (!waf2Transaction.getResponseBody().empty()) {
                for (const auto &rx : rxes) {
                    boost::smatch matcher;
                    if (NGEN::Regex::regexSearch(
                        __FILE__,
                        __LINE__,
                        waf2Transaction.getResponseBody().c_str(),
                        matcher,
                        *rx
                    )) {
                        return true;
                    }
                }
                return false;
            } else {
                return false;
            }
        } else if (tagLower == "headername") {
            if (!waf2Transaction.checkIsHeaderOverrideScanRequired()) {
                dbgDebug(D_WAAP_OVERRIDE) << "Header name override scan is not required";
                return false;
            }
            for (const auto &rx : rxes) {
                for (auto& hdr_pair : waf2Transaction.getHdrPairs()) {
                    std::string value = hdr_pair.first;
                    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                    if (REGX_MATCH(value)) {
                        return true;
                    }
                }
            }
            return false;
        } else if (tagLower == "headervalue") {
            if (!waf2Transaction.checkIsHeaderOverrideScanRequired()) {
                dbgDebug(D_WAAP_OVERRIDE) << "Header value override scan is not required";
                return false;
            }
            for (const auto &rx : rxes) {
                for (auto& hdr_pair : waf2Transaction.getHdrPairs()) {
                    std::string value = hdr_pair.second;
                    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
                    if (REGX_MATCH(value)) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
    catch (std::runtime_error & e) {
        dbgDebug(D_WAAP_OVERRIDE) << "RegEx match for tag " << tag << " failed due to: " << e.what();
        return false;
    }
    // Unknown tag: should not occur
    dbgDebug(D_WAAP) << "Invalid override tag: " << tag;
    return false;
}
