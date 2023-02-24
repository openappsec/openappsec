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
#include <boost/regex.hpp>
#include "WaapOverrideFunctor.h"
#include "Waf2Engine.h"
#include "CidrMatch.h"
#include "agent_core_utilities.h"
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP_OVERRIDE);

WaapOverrideFunctor::WaapOverrideFunctor(Waf2Transaction& waf2Transaction) :waf2Transaction(waf2Transaction)
{
}

bool WaapOverrideFunctor::operator()(const std::string& tag, const Waap::Util::CIDRData& value) {
    if (tag == "sourceip") {
        dbgDebug(D_WAAP_OVERRIDE) << "Remote IP Address : " << waf2Transaction.getRemoteAddr() << " CIDR: " <<
            value.cidrString;
        std::string sourceIp = waf2Transaction.getRemoteAddr();
        // match sourceIp against the cidr
        return Waap::Util::cidrMatch(sourceIp, value);
    }
    else if (tag == "sourceidentifier") {
        dbgDebug(D_WAAP_OVERRIDE) << "Remote IP Address : " << waf2Transaction.getRemoteAddr() << " CIDR: " <<
            value.cidrString;
        std::string sourceIp = waf2Transaction.getSourceIdentifier();
        // match source against the cidr
        return Waap::Util::cidrMatch(sourceIp, value);
    }

    return false;
}

bool WaapOverrideFunctor::operator()(const std::string& tag, const boost::regex& rx)
{
    boost::cmatch what;
    try {
        if (tag == "url") {
            return NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getUriStr().c_str(), what, rx);
        }
        else if (tag == "hostname") {
            return NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getHost().c_str(), what, rx);
        }
        else if (tag == "sourceidentifier") {
            return NGEN::Regex::regexMatch(
                __FILE__,
                __LINE__,
                waf2Transaction.getSourceIdentifier().c_str(),
                what,
                rx
            );
        }
        else if (tag == "keyword") {
            for (const std::string& keywordStr : waf2Transaction.getKeywordMatches()) {
                if (NGEN::Regex::regexMatch(__FILE__, __LINE__, keywordStr.c_str(), what, rx)) {
                    return true;
                }
            }
            return false;
        }
        else if (tag == "paramname" || tag == "paramName") {
            for (const DeepParser::KeywordInfo& keywordInfo : waf2Transaction.getKeywordInfo()) {
                if (NGEN::Regex::regexMatch(__FILE__, __LINE__, keywordInfo.getName().c_str(), what, rx)) {
                    return true;
                }
            }
            if (NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getParamKey().c_str(), what, rx)) {
                return true;
            }
            if (NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getParam().c_str(), what, rx)) {
                return true;
            }
            return false;
        }
        else if (tag == "paramvalue" || tag == "paramValue") {
            for (const DeepParser::KeywordInfo& keywordInfo : waf2Transaction.getKeywordInfo()) {
                if (NGEN::Regex::regexMatch(__FILE__, __LINE__, keywordInfo.getValue().c_str(), what, rx)) {
                    return true;
                }
            }
            if (NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getSample().c_str(), what, rx)) {
                return true;
            }
            return false;
        }
        else if (tag == "paramlocation" || tag == "paramLocation") {
            return NGEN::Regex::regexMatch(__FILE__, __LINE__, waf2Transaction.getLocation().c_str(), what, rx);
        }
        else if (tag == "responsebody" || tag == "responseBody") {
            waf2Transaction.getResponseInspectReasons().setApplyOverride(true);
            if (!waf2Transaction.getResponseBody().empty()) {
                boost::smatch matcher;
                return NGEN::Regex::regexSearch(__FILE__, __LINE__,
                        waf2Transaction.getResponseBody().c_str(), matcher, rx);
            } else {
                return false;
            }
        }
    }
    catch (std::runtime_error & e) {
        dbgDebug(D_WAAP_OVERRIDE) << "RegEx match for tag " << tag << " failed due to: " << e.what();
        return false;
    }

    // Unknown tag: should not occur
    dbgWarning(D_WAAP) << "Invalid override tag:" << tag;
    return false;
}
