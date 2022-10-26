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
#include "WaapOpenRedirectPolicy.h"
#include <set>
#include <string>
#include <memory>
#include "debug.h"

namespace Waap {
namespace OpenRedirect {

class State {
public:
    void collect(const char* v, size_t v_len, const std::string &hostStr);
    bool testRedirect(const std::string &redirectUrl) const;
    bool empty() const;
private:
    std::set<std::string> m_openRedirectUrls;
};

}
}
