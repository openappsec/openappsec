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

#include "WaapEnums.h"

class I_WaapAssetState {
public:
    virtual void updateScores() = 0;
    virtual std::string getWaapDataFileName() const = 0;
    virtual std::string getWaapDataDir() const = 0;
    virtual bool isKeywordOfType(const std::string& keyword, ParamType type) const = 0;
    virtual bool isBinarySampleType(const std::string & sample) const = 0;
    virtual bool isWBXMLSampleType(const std::string & sample) const = 0;
    virtual std::set<std::string> getSampleType(const std::string& sample) const = 0;
};
