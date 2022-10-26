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

#include "ConfidenceFile.h"

ConfidenceFileDecryptor::ConfidenceFileDecryptor()
{
}

Maybe<ConfidenceCalculator::ConfidenceSet> ConfidenceFileDecryptor::getConfidenceSet() const
{
    if (!confidence_set.get().empty()) return confidence_set.get();
    return genError("failed to get file");
}

Maybe<ConfidenceCalculator::ConfidenceLevels> ConfidenceFileDecryptor::getConfidenceLevels() const
{
    if (!confidence_levels.get().empty()) return confidence_levels.get();
    return genError("failed to get confidence levels");
}


ConfidenceFileEncryptor::ConfidenceFileEncryptor(const ConfidenceCalculator::ConfidenceSet& _confidence_set,
    const ConfidenceCalculator::ConfidenceLevels& _confidence_levels) :
    confidence_set(_confidence_set), confidence_levels(_confidence_levels)
{
}
