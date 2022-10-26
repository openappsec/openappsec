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

#include "WaapOpenRedirect.h"
#include "WaapOpenRedirectPolicy.h"
#include "Waf2Util.h"
#include <string>
#include <set>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string.hpp>

USE_DEBUG_FLAG(D_WAAP);

// Max number of openredirect URLs extracted from URL parameters, that are stored
#define MAX_OPENREDIRECT_URLS 25

namespace Waap {
namespace OpenRedirect {

void State::collect(const char* v, size_t v_len, const std::string &hostStr) {
    std::string urlDomain;

    if (v_len>8 && memcaseinsensitivecmp(v, 8, "https://", 8)) {
        // Detect https URL and extract domain name
        urlDomain = std::string(v+8, v_len-8);
    }
    else if (v_len>7 && memcaseinsensitivecmp(v, 7, "http://", 7)) {
        // Detect http URL and extract domain name
        urlDomain = std::string(v+7, v_len-7);
    }

    // urlDomain starts with domain name (without the schema), which can is terminated by the '/' character
    urlDomain = urlDomain.substr(0, urlDomain.find('/', 0));

    // For comparison, consider domain names from the Host: header and from the value URL, without port numbers
    std::string urlDomainNoPort = urlDomain.substr(0, urlDomain.find(":", 0));
    std::string hostStrNoPort = hostStr.substr(0, hostStr.find(":", 0));

    // Avoid adding URLs whose "domain" part is equal to the site's hostname (take from the request's Host header)
    // Also, limit number of openredirect URLs we remember
    if (!urlDomainNoPort.empty() && urlDomainNoPort != hostStrNoPort &&
        m_openRedirectUrls.size() < MAX_OPENREDIRECT_URLS)
    {
        m_openRedirectUrls.insert(boost::algorithm::to_lower_copy(std::string(v, v_len)));
        dbgTrace(D_WAAP) << "Waf2Transaction::collectUrlsForOpenRedirect(): adding url '" <<
            std::string(v, v_len) << "'";
    }
}

bool
State::testRedirect(const std::string &redirectUrl) const
{
    if (redirectUrl.empty()) {
        return false;
    }

    std::string redirectUrlLower = boost::algorithm::to_lower_copy(redirectUrl);
    
    if (!redirectUrlLower.empty())
    {
        for (const auto &collectedUrl : m_openRedirectUrls) {
            // Detect whether redirect URL (from the Location response header) starts with one of the collected urls
            // Note that the collected URLs are already stored lowercase
            if (boost::algorithm::starts_with(redirectUrlLower, collectedUrl)) {
                return true;
            }
        }
    }

    return false;
}

bool
State::empty() const
{
    return m_openRedirectUrls.empty();
}

}
}
