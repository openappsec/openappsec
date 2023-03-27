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
#ifndef __WAAP_CONFIG_APPLICATION_H__
#define __WAAP_CONFIG_APPLICATION_H__

#include <set>

#include "WaapConfigBase.h"
#include "log_generator.h"
#include "i_environment.h"
#include "debug.h"

class WaapConfigApplication
        :
    public WaapConfigBase,
    Singleton::Consume<I_Environment>
{
public:
    WaapConfigApplication();

    bool operator==(const WaapConfigApplication& other) const;

    virtual const std::string& get_PracticeSubType() const;

    void load(cereal::JSONInputArchive& ar);
    void printMe(std::ostream& os) const;
    static bool getWaapSiteConfig(WaapConfigApplication& ngenSiteConfig);
    static void notifyAssetsCount();
    static void clearAssetsCount();

private:
    static const std::string s_PracticeSubType;
    static std::set<std::string> assets_ids;
    static std::set<std::string> assets_ids_aggregation;
};

#endif // __WAAP_CONFIG_APPLICATION_H__
