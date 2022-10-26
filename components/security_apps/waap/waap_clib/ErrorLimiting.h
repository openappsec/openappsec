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

#include "WaapAssetState.h"
#include "waap.h"
#include <string>
#include <chrono>
#include <memory>
#include <cereal/types/vector.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/archives/json.hpp>

namespace Waap
{
namespace ErrorLimiting
{
    struct ErrorLimiter
    {
        struct Policy
        {
            template <typename _A>
            void serialize(_A &ar)
            {
                ar(
                    cereal::make_nvp("interval", interval),
                    cereal::make_nvp("events", events),
                    cereal::make_nvp("type", type)
                );

                if(type == "quarantine")
                {
                    ar(cereal::make_nvp("blockingTime", blockingTime));
                }
            }
            unsigned interval = 0;
            unsigned events = 0;
            std::string type;
            int blockingTime = 0;
        };

        class ErrorLimitingEnforcement
        {
        public:
            template <typename _A>
            ErrorLimitingEnforcement(_A &ar)
            :
            enable(false)
            {
                std::string level;
                ar(cereal::make_nvp("errorLimitingEnforcement", level));
                level = boost::algorithm::to_lower_copy(level);
                if (level == "prevent") {
                    enable = true;
                }
            }

            bool operator==(const ErrorLimitingEnforcement &other) const;

            bool enable;
        };

        Policy m_errorLimiterPolicy;
        ErrorLimitingEnforcement m_errorLimiting;

        bool getErrorLimitingEnforcementStatus();

        template <typename _A>
        ErrorLimiter(_A& ar) :
        m_errorLimiting(ar)
        {
            ar(cereal::make_nvp("errorLimiter", m_errorLimiterPolicy));
        };

    };

    bool enforce(
        const std::string& sourceIdentifier,
        const std::string& uriStr,
        const std::shared_ptr<WaapAssetState>& pWaapAssetState,
        bool& log);

}
}
