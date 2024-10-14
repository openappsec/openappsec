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
#include <set>
#include <boost/regex.hpp>

namespace Waap {
namespace Util {

// Custom comparator for std::shared_ptr<boost::regex>
struct RegexComparator {
    bool operator()(const std::shared_ptr<boost::regex>& lhs, const std::shared_ptr<boost::regex>& rhs) const {
        // Compare the actual regex patterns by string representation
        return lhs->str() < rhs->str();
    }
};

std::string regexSetToString(const std::set<std::shared_ptr<boost::regex>, RegexComparator> &regexSet);

}
}
