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
#ifndef __WAAP_CONFIG_API_H__
#define __WAAP_CONFIG_API_H__

#include <set>

#include "WaapConfigBase.h"
#include "log_generator.h"
#include "debug.h"

class WaapConfigAPI : public WaapConfigBase
{
public:
    WaapConfigAPI();

    void load(cereal::JSONInputArchive& ar);
    bool operator==(const WaapConfigAPI& other) const;
    void printMe(std::ostream& os) const;

    virtual const std::string& get_PracticeSubType() const;
    static bool getWaapAPIConfig(WaapConfigAPI &ngenAPIConfig);
    static void notifyAssetsCount();
    static void clearAssetsCount();

private:

    static const std::string s_PracticeSubType;
    static std::set<std::string> assets_ids;
    static std::set<std::string> assets_ids_aggregation;
};

#endif // __WAAP_CONFIG_API_H__
