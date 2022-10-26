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

#include "log_streams.h"

#include <sstream>

#include "debug.h"

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_REPORT);

void
DebugStream::sendLog(const Report &log)
{
    stringstream ss;
    {
        JSONOutputArchive ar(ss);
        log.serialize(ar);
    }
    dbgInfo(D_REPORT) << ss.str();
}
