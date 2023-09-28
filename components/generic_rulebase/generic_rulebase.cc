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

#include "generic_rulebase/generic_rulebase.h"

#include <unordered_set>

#include "generic_rulebase/evaluators/trigger_eval.h"
#include "generic_rulebase/evaluators/practice_eval.h"
#include "generic_rulebase/evaluators/parameter_eval.h"
#include "generic_rulebase/evaluators/zone_eval.h"
#include "generic_rulebase/evaluators/asset_eval.h"
#include "generic_rulebase/evaluators/query_eval.h"
#include "generic_rulebase/evaluators/connection_eval.h"
#include "generic_rulebase/evaluators/http_transaction_data_eval.h"
#include "generic_rulebase/zone.h"
#include "generic_rulebase/triggers_config.h"
#include "singleton.h"
#include "common.h"
#include "debug.h"
#include "cache.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

class GenericRulebase::Impl : Singleton::Provide<I_GenericRulebase>::From<GenericRulebase>
{
public:
    void init() {}
    void fini() {}

    void preload();

    Maybe<Zone, Config::Errors> getLocalZone() const override { return getZoneConfig(true); }
    Maybe<Zone, Config::Errors> getOtherZone() const override { return getZoneConfig(false); }

    set<ParameterBehavior> getBehavior(const ParameterKeyValues &key_value_pairs) const override;

private:
    Maybe<Zone, Config::Errors>
    getZoneConfig(bool is_local_zone) const
    {
        ScopedContext asset_location_ctx;
        asset_location_ctx.registerValue<bool>("is local asset", is_local_zone);
        return getConfiguration<Zone>("rulebase", "zones");
    }
};

void
GenericRulebase::Impl::preload()
{
    addMatcher<TriggerMatcher>();
    addMatcher<PracticeMatcher>();
    addMatcher<ParameterMatcher>();
    addMatcher<ZoneMatcher>();
    addMatcher<AssetMatcher>();
    addMatcher<QueryMatcher>();
    addMatcher<IpAddressMatcher>();
    addMatcher<SourceIpMatcher>();
    addMatcher<DestinationIpMatcher>();
    addMatcher<SourcePortMatcher>();
    addMatcher<ListeningPortMatcher>();
    addMatcher<IpProtocolMatcher>();
    addMatcher<UrlMatcher>();
    addMatcher<EqualHost>();
    addMatcher<WildcardHost>();
    addMatcher<EqualListeningIP>();
    addMatcher<EqualListeningPort>();
    addMatcher<BeginWithUri>();
    BasicRuleConfig::preload();
    LogTriggerConf::preload();
    ParameterException::preload();
    registerExpectedConfiguration<Zone>("rulebase", "zones");
    registerExpectedConfigFile("zones", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("triggers", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("rules", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("parameters", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("exceptions", Config::ConfigFileType::Policy);

}

set<ParameterBehavior>
GenericRulebase::Impl::getBehavior(const ParameterKeyValues &key_value_pairs) const
{
    auto &exceptions = getConfiguration<ParameterException>("rulebase", "exception");

    if (!exceptions.ok()) {
        dbgTrace(D_RULEBASE_CONFIG) << "Could not find any exception with the current rule's context";
        return {};
    }
    return (*exceptions).getBehavior(key_value_pairs);
}

GenericRulebase::GenericRulebase() : Component("GenericRulebase"), pimpl(make_unique<Impl>()) {}

GenericRulebase::~GenericRulebase() {}

void
GenericRulebase::init()
{
    pimpl->init();
}

void
GenericRulebase::fini()
{
    pimpl->fini();
}

void
GenericRulebase::preload()
{
    pimpl->preload();
}
