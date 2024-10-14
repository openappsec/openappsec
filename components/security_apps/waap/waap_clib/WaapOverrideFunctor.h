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

namespace Waap {
    namespace Util {
        struct CIDRData; // forward decleration
        struct RegexComparator;
    }
}

class Waf2Transaction;

// Functor used to match Override rules against request data
class WaapOverrideFunctor {
public:
    WaapOverrideFunctor(Waf2Transaction &waf2Transaction);

    bool operator()(const std::string &tag, const std::vector<Waap::Util::CIDRData> &values);

    bool operator()(
        const std::string &tag,
        const std::set<std::shared_ptr<boost::regex>, Waap::Util::RegexComparator> &rxes
    );

private:
    Waf2Transaction &waf2Transaction;
};
