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

#ifndef __WAAP_CONVERSIONS_H__
#define __WAAP_CONVERSIONS_H__

#include "WaapEnums.h"
#include "i_waapConfig.h"

namespace Waap {
namespace Conversions {
    ThreatLevel convertFinalScoreToThreatLevel(double finalScore);
    bool shouldDoWafBlocking(const IWaapConfig* pSitePolicy, ThreatLevel threatLevel);
}
}

#endif // __WAAP_CONVERSIONS_H__
