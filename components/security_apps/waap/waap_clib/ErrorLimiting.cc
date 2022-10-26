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

#include "WaapAssetState.h"
#include "waap.h"
#include <string>
#include <chrono>
#include <memory>
#include <cereal/types/vector.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/archives/json.hpp>
#include "ErrorLimiting.h"

namespace Waap
{
namespace ErrorLimiting
{

bool
ErrorLimiter::getErrorLimitingEnforcementStatus(){
    return m_errorLimiting.enable;
}

bool enforce(
    const std::string& sourceIdentifier,
    const std::string& uriStr,
    const std::shared_ptr<WaapAssetState>& pWaapAssetState,
    bool& log)
    {

    dbgTrace(D_WAAP) << "ErrorLimiting::enforce:: response code: 404 :: error Limiting.";

    // Get current clock time
    I_TimeGet* timer = Singleton::Consume<I_TimeGet>::by<WaapComponent>();

    // The error limiting state tracks error limiting information for all sources
    std::shared_ptr<Waap::RateLimiting::State> errorLimitingState = pWaapAssetState->getErrorLimitingState();

    std::chrono::seconds now = std::chrono::duration_cast<std::chrono::seconds>(timer->getMonotonicTime());
    if (errorLimitingState && (errorLimitingState->execute(sourceIdentifier, uriStr, now, log) == false)) {
        // block request due to error limiting
        return true;
    }

    return false;
}

}
}
