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

#include "WaapOpenRedirectPolicy.h"
#include "Waf2Util.h"
#include <string>

namespace Waap {
namespace OpenRedirect {

Policy::Policy()
:
enable(false),
enforce(false)
{
}

bool
Policy::operator==(const Policy &other) const
{
    return enable == other.enable &&
        enforce == other.enforce;
}

}
}
