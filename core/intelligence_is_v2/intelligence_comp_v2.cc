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

#include "intelligence_comp_v2.h"

#include <fstream>

#include "cache.h"
#include "config.h"
#include "table.h"
#include "intelligence_is_v2/query_response_v2.h"

using namespace std;
using namespace chrono;
using namespace Intelligence_IS_V2;

USE_DEBUG_FLAG(D_INTELLIGENCE);

class IntelligenceComponentV2::Impl
        :
    Singleton::Provide<I_Intelligence_IS_V2>::From<IntelligenceComponentV2>
{
public:
    class OfflineIntelligeceHandler
    {
    public:
        void
        init()
        {
            filesystem_prefix = getFilesystemPathConfig();
            dbgTrace(D_INTELLIGENCE) << "OfflineIntelligeceHandler init. file systen prefix: " << filesystem_prefix;
            offline_intelligence_path = getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/offline/intelligence",
                "intelligence",
                "offline intelligence path"
            );
        }

        Maybe<string>
        getValueByIdentifier(const string &identifier) const
        {
            string asset_file_path = offline_intelligence_path + "/" + identifier;
            ifstream asset_info(asset_file_path);
            if (!asset_info.is_open()) {
                return genError("Could not open file: " + asset_file_path);
            }

            stringstream info_txt;
            info_txt << asset_info.rdbuf();
            asset_info.close();
            return info_txt.str();
        }

    private:
        string filesystem_prefix = "";
        string offline_intelligence_path = "";
    };

    void
    init()
    {
        offline_mode_only = getConfigurationWithDefault<bool>(false, "intelligence", "offline intelligence only");
        registerConfigLoadCb([&]() {
            offline_mode_only = getConfigurationWithDefault<bool>(false, "intelligence", "offline intelligence only");
        });
        offline_intelligence.init();

        message = Singleton::Consume<I_Messaging>::by<IntelligenceComponentV2>();
        timer = Singleton::Consume<I_TimeGet>::by<IntelligenceComponentV2>();
        mainloop = Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();
    }

    I_Messaging *
    getMessaging() const override
    {
        return message != NULL ? message : Singleton::Consume<I_Messaging>::by<IntelligenceComponentV2>();
    }

    I_TimeGet *
    getTimer() const override
    {
        return timer != NULL ? timer : Singleton::Consume<I_TimeGet>::by<IntelligenceComponentV2>();
    }

    I_MainLoop *
    getMainloop() const override
    {
        return mainloop != NULL ? mainloop : Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();
    }

    Maybe<string>
    getOfflineInfoString(const SerializableQueryFilter &query) const override
    {
        string ip_attr_key = "mainAttributes.ip";
        string identifier_value = move(query.getConditionValueByKey(ip_attr_key));
        if (identifier_value == "") {
            return genError("could not find IP main attribute in the given query.");
        }
        return offline_intelligence.getValueByIdentifier(identifier_value);
    }

    bool
    getIsOfflineOnly() const override
    {
        return offline_mode_only;
    }

private:
    OfflineIntelligeceHandler    offline_intelligence;
    bool                         offline_mode_only = false;
    I_Messaging                  *message = nullptr;
    I_TimeGet                    *timer = nullptr;
    I_MainLoop                   *mainloop = nullptr;
};

IntelligenceComponentV2::IntelligenceComponentV2()
        :
    Component("IntelligenceComponentV2"),
    pimpl(make_unique<Impl>())
{}

IntelligenceComponentV2::~IntelligenceComponentV2() {}

void IntelligenceComponentV2::init() { pimpl->init(); }

void
IntelligenceComponentV2::preload()
{
    registerExpectedConfiguration<string>("intelligence", "offline intelligence path");
    registerExpectedConfiguration<bool>("intelligence", "offline intelligence only");
    registerExpectedConfiguration<uint>("intelligence", "maximum request overall time");
    registerExpectedConfiguration<uint>("intelligence", "maximum request lap time");
    registerExpectedSetting<string>("intelligence", "local intelligence server ip");
    registerExpectedSetting<uint>("intelligence", "local intelligence server secondary port");
    registerExpectedSetting<uint>("intelligence", "local intelligence server primary port");

    registerExpectedConfigFile("agent-intelligence", Config::ConfigFileType::Policy);
}
