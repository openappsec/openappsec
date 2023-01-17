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
#include "debug.h"

namespace Waap {
namespace Csrf {

struct Policy {
    Policy();

    template <typename _A>
    Policy(_A &ar)
    :
    enable(false),
    enforce(false)
    {
        bool web_attack_on;
        ar(cereal::make_nvp("webAttackMitigation", web_attack_on));
        if (!web_attack_on) return;

        std::string level;
        ar(cereal::make_nvp("csrfProtection", level));
        level = boost::algorithm::to_lower_copy(level);
        if (level == "detect") {
            enable = true;
        }
        else if (level == "prevent") {
            enable = true;
            enforce = true;
        }
    }

    bool operator==(const Policy &other) const;

    bool enable;
    bool enforce;
};

}
}
