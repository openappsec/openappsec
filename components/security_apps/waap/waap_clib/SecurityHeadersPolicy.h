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

#pragma once
#include <cereal/types/string.hpp>
#include <string>
#include <memory>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

namespace Waap {
namespace SecurityHeaders {
struct Policy {
    struct StrictTransportSecurity {
        void setDefaults()
        {
            maxAge = "31536000";
            includeSubDomains = true;
            preload = false;
            buildInjectStr();
        }

        template <typename _A>
        void serialize(_A &ar) {
            ar(cereal::make_nvp("maxAge", maxAge));
            ar(cereal::make_nvp("includeSubDomains", includeSubDomains));
            ar(cereal::make_nvp("preload", preload));
            buildInjectStr();
        }

        void buildInjectStr();
        bool operator==(const StrictTransportSecurity &other) const;

        const std::string headerName = "Strict-Transport-Security";
        std::string maxAge;
        bool includeSubDomains;
        bool preload;
        std::string directivesStr;
        // string that define exactly how the header should be inject after collecting all data.
        std::pair<std::string, std::string> headerDetails;
    };

    struct XFrameOptions {

        void setDefaults()
        {
            directivesStr = sameOrigin;
            buildInjectStr();
        }

        template <typename _A>
        void serialize(_A &ar) {

            std::string value;
            ar(cereal::make_nvp("directive", value));
            if(boost::iequals(value, "sameOrigin"))
            {
                directivesStr = sameOrigin;
            }
            else if(boost::iequals(value, "deny"))
            {
                directivesStr = deny;
            }
            else
            {
                throw cereal::Exception(
                    "Invalid value for SecurityHeaders::Policy::XFrameOptions::directive='" + value + "'");
            }

            buildInjectStr();
        }

        void buildInjectStr();
        bool operator==(const XFrameOptions &other) const;

        const std::string sameOrigin = "SAMEORIGIN";
        const std::string deny = "DENY";
        const std::string headerName = "X-Frame-Options";
        std::string directivesStr;
        // string that define exactly how the header should be inject after collecting all data.
        std::pair<std::string, std::string> headerDetails;
    };

    struct XContentTypeOptions
    {
        void setDefaults()
        {
            directivesStr = nosniff;
            buildInjectStr();
        }

        template <typename _A>
        void serialize(_A &ar) {

            std::string value;
            ar(cereal::make_nvp("directive", value));
            if(boost::iequals(value, "nosniff"))
            {
                directivesStr = nosniff;
            }
            else
            {
                throw cereal::Exception(
                    "Invalid value for SecurityHeaders::Policy::XContentTypeOptions::directive='" + value + "'");
            }

            buildInjectStr();
        }

        void buildInjectStr();
        bool operator==(const XContentTypeOptions &other) const;
        const std::string headerName = "X-Content-Type-Options";
        const std::string nosniff = "nosniff";
        std::string directivesStr;
        // string that define exactly how the header should be inject after collecting all data.
        std::pair<std::string, std::string> headerDetails;
    };

    struct Headers {

        template <typename _A>
        void serialize(_A &ar) {
            try
            {
                ar(cereal::make_nvp("strictTransportSecurity", hsts));
                headersInjectStr.push_back(
                    std::make_pair(hsts.headerDetails.first, hsts.headerDetails.second));
            }
            catch (std::runtime_error& e)
            {
                dbgTrace(D_WAAP) << "Strict-Transport-Security header is not configured. Loading defaults.";
                hsts.setDefaults();
                headersInjectStr.push_back(
                    std::make_pair(hsts.headerDetails.first, hsts.headerDetails.second));
            }
            try
            {
                ar(cereal::make_nvp("xFrameOptions", xFrameOptions));
                headersInjectStr.push_back(
                    std::make_pair(xFrameOptions.headerDetails.first, xFrameOptions.headerDetails.second));
            }
            catch (std::runtime_error& e)
            {
                dbgTrace(D_WAAP) << "X-Frame-Options header is not configured. Loading defaults.";
                xFrameOptions.setDefaults();
                headersInjectStr.push_back(
                    std::make_pair(xFrameOptions.headerDetails.first, xFrameOptions.headerDetails.second));
            }
            try
            {
                ar(cereal::make_nvp("xContentTypeOptions", xContentTypeOptions));
                headersInjectStr.push_back(
                    std::make_pair(xContentTypeOptions.headerDetails.first, xContentTypeOptions.headerDetails.second));
            }
            catch (std::runtime_error& e)
            {
                dbgTrace(D_WAAP) << "X Content Type Options header is not configured. Loading defaults.";
                xContentTypeOptions.setDefaults();
                headersInjectStr.push_back(
                    std::make_pair(xContentTypeOptions.headerDetails.first, xContentTypeOptions.headerDetails.second));
            }
        }

        bool operator==(const Headers &other) const;
        // will contain all strings that should be injected as headers.
        std::vector<std::pair<std::string, std::string>> headersInjectStr;
        StrictTransportSecurity hsts;
        XFrameOptions xFrameOptions;
        XContentTypeOptions xContentTypeOptions;
    };

    class SecurityHeadersEnforcement
    {
    public:
        template <typename _A>
        SecurityHeadersEnforcement(_A &ar)
        :
        enable(false)
        {
            std::string level;
            ar(cereal::make_nvp("securityHeadersEnforcement", level));
            level = boost::algorithm::to_lower_copy(level);
            if (level == "prevent") {
                enable = true;
            }
        }

        bool operator==(const Policy::SecurityHeadersEnforcement &other) const;

        bool enable;
    };

    Headers headers;
    SecurityHeadersEnforcement m_securityHeaders;

    bool operator==(const Policy &other) const;

    template <typename _A>
    Policy(_A& ar) : m_securityHeaders(ar) {
        ar(cereal::make_nvp("securityHeaders", headers));
    }

};
class State {
    public:
        const std::shared_ptr<Policy> policy;
        State(const std::shared_ptr<Policy> &policy);
        std::vector<std::pair<std::string, std::string>> headersInjectStrs;
};

}
}
