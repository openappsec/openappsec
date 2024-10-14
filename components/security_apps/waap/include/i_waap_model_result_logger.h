// Copyright (C) 2024 Check Point Software Technologies Ltd. All rights reserved.

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

class IWaf2Transaction;
struct Waf2ScanResult;
namespace Waap {
namespace Scores {
struct ModelLoggingSettings;
}
}

class I_WaapModelResultLogger {
public:
    virtual ~I_WaapModelResultLogger() {}

    virtual void
    logModelResult(
        Waap::Scores::ModelLoggingSettings &settings,
        IWaf2Transaction* transaction,
        Waf2ScanResult &res,
        std::string modelName,
        std::string otherModelName,
        double newScore,
        double baseScore) = 0;
};
