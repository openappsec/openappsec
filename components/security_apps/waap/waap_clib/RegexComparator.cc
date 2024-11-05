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

#include "RegexComparator.h"
#include <sstream>

namespace Waap {
namespace Util {

std::string regexSetToString(const std::set<std::shared_ptr<boost::regex>, RegexComparator> &regexSet) {
    std::stringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &regexPtr : regexSet) {
        if (!first) ss << ", ";
        if (regexPtr) {
            first = false;
            ss << regexPtr->str();
        }
    }
    ss << "]";
    return ss.str();
}

}
}
