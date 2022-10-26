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
#include <cereal/types/vector.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <vector>
#include <string>
#include <memory>
#include "debug.h"

USE_DEBUG_FLAG(D_WAAP);

namespace Waap {
namespace Trigger {
using boost::algorithm::to_lower_copy;

struct Log {
    template <typename _A>
    void serialize(_A &ar) {
        ar(cereal::make_nvp("verbosity", verbosity));
        verbosity = to_lower_copy(verbosity);
        ar(cereal::make_nvp("complianceWarnings", complianceWarnings));
        ar(cereal::make_nvp("complianceViolations", complianceViolations));
        ar(cereal::make_nvp("acAllow", acAllow));
        ar(cereal::make_nvp("acDrop", acDrop));
        ar(cereal::make_nvp("tpDetect", tpDetect));
        ar(cereal::make_nvp("tpPrevent", tpPrevent));
        ar(cereal::make_nvp("webRequests", webRequests));
        ar(cereal::make_nvp("webUrlPath", webUrlPath));
        ar(cereal::make_nvp("webUrlQuery", webUrlQuery));
        ar(cereal::make_nvp("webBody", webBody));
        ar(cereal::make_nvp("logToCloud", logToCloud));
        ar(cereal::make_nvp("logToAgent", logToAgent));

        try
        {
            ar(cereal::make_nvp("webHeaders", webHeaders));
        }
        catch (const cereal::Exception &e)
        {
            ar.setNextName(nullptr);
            dbgDebug(D_WAAP) << "failed to load webHeaders field. Error: " << e.what();
        }

        try
        {
            ar(cereal::make_nvp("extendLogging", extendLogging));
        }
        catch(const cereal::Exception &e)
        {
            ar.setNextName(nullptr);
            dbgDebug(D_WAAP) << "Failed to load extendedLogging field. Error: " << e.what();
        }


        if (extendLogging)
        {
            try
            {
                ar(cereal::make_nvp("extendLoggingMinSeverity", extendLoggingMinSeverity));
            }
            catch(const cereal::Exception &e)
            {
                ar.setNextName(nullptr);
                dbgDebug(D_WAAP) << "Failed to load extendLoggingMinSeverity field. Error: " << e.what();
            }

            try
            {
                ar(cereal::make_nvp("responseCode", responseCode));
            }
            catch(const cereal::Exception &e)
            {
                ar.setNextName(nullptr);
                dbgDebug(D_WAAP) << "Failed to load responseCode field. Error: " << e.what();
            }

            try
            {
                ar(cereal::make_nvp("responseBody", responseBody));
            }
            catch(const cereal::Exception &e)
            {
                ar.setNextName(nullptr);
                dbgDebug(D_WAAP) << "Failed to load responseBody field. Error: " << e.what();
            }
        }
    }

    Log();
    bool operator==(const Log &other) const;

    std::string verbosity;
    bool complianceWarnings;
    bool complianceViolations;
    bool acAllow;
    bool acDrop;
    bool tpDetect;
    bool tpPrevent;
    bool webRequests;
    bool webUrlPath;
    bool webUrlQuery;
    bool webHeaders;
    bool webBody;
    bool logToCloud;
    bool logToAgent;
    bool extendLogging;
    bool responseCode;
    bool responseBody;
    std::string extendLoggingMinSeverity;
};

struct Trigger {
    template <typename _A>
    void serialize(_A &ar) {
        ar(cereal::make_nvp("$triggerType", triggerType));
        triggerType = to_lower_copy(triggerType);

        // Currently, only load triggers of type "log".
        if (triggerType == "log") {
            ar(cereal::make_nvp("log", *log));
        }
    }

    Trigger();
    bool operator==(const Trigger &other) const;

    std::string triggerType;
    std::shared_ptr<Log> log;
};

struct Policy {
    template <typename _A>
    Policy(_A &ar) {
        ar(cereal::make_nvp("triggers", triggers));
    }

    bool operator==(const Policy &other) const;

    std::vector<Waap::Trigger::Trigger> triggers;
};

}
}
