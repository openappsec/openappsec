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
#include "ConfidenceCalculator.h"

class ConfidenceFileDecryptor : public RestGetFile
{
public:
    ConfidenceFileDecryptor();

    Maybe<ConfidenceCalculator::ConfidenceSet>
        getConfidenceSet() const;
    Maybe<ConfidenceCalculator::ConfidenceLevels>
        getConfidenceLevels() const;

private:
    S2C_PARAM(ConfidenceCalculator::ConfidenceSet, confidence_set);
    S2C_OPTIONAL_PARAM(ConfidenceCalculator::ConfidenceLevels, confidence_levels);
};

class ConfidenceFileEncryptor : public RestGetFile
{
public:
    ConfidenceFileEncryptor(const ConfidenceCalculator::ConfidenceSet& _confidence_set,
        const ConfidenceCalculator::ConfidenceLevels& _confidence_levels);

private:
    C2S_PARAM(ConfidenceCalculator::ConfidenceSet, confidence_set);
    C2S_PARAM(ConfidenceCalculator::ConfidenceLevels, confidence_levels);
};
