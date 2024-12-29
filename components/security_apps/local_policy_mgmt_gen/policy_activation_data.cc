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

#include "policy_activation_data.h"
#include "customized_cereal_map.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static const set<string> valid_modes = {
    "prevent-learn",
    "detect-learn",
    "prevent",
    "detect",
    "inactive"
};

void
PolicyActivationMetadata::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "PolicyActivationMetadata load";
    parseAppsecJSONKey<string>("name", name, archive_in);
}

void
EnabledPolicy::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading policyActivation enabled policy";
    parseMandatoryAppsecJSONKey<vector<string>>("hosts", hosts, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("mode", mode, archive_in, "detect");
    if (valid_modes.count(mode) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec policy activation mode invalid: " << mode;
        mode = "detect";
    }
}

const string &
EnabledPolicy::getName() const
{
    return name;
}

const vector<string> &
EnabledPolicy::getHosts() const
{
    return hosts;
}

void
PolicyActivationSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "PolicyActivationSpec load";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseMandatoryAppsecJSONKey<vector<EnabledPolicy>>("enabledPolicies", policies, archive_in);
}

const vector<EnabledPolicy> &
PolicyActivationSpec::getPolicies() const
{
    return policies;
}

void
SinglePolicyActivationData::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading single policy activation data";
    parseAppsecJSONKey<string>("apiVersion", api_version, archive_in);
    parseAppsecJSONKey<string>("kind", kind, archive_in);
    parseAppsecJSONKey<PolicyActivationMetadata>("metadata", metadata, archive_in);
    parseAppsecJSONKey<PolicyActivationSpec>("spec", spec, archive_in);
}

const PolicyActivationSpec &
SinglePolicyActivationData::getSpec() const
{
    return spec;
}

bool
PolicyActivationData::loadJson(const string &json)
{
    string modified_json = json;
    modified_json.pop_back();
    stringstream in;
    in.str(modified_json);
    dbgTrace(D_LOCAL_POLICY) << "Loading policy activations data";
    try {
        cereal::JSONInputArchive in_ar(in);
        in_ar(
            cereal::make_nvp("apiVersion", api_version),
            cereal::make_nvp("items", items)
        );
    } catch (cereal::Exception &e) {
        dbgError(D_LOCAL_POLICY) << "Failed to load policy activations data JSON. Error: " << e.what();
        return false;
    }
    return true;
}

const vector<SinglePolicyActivationData> &
PolicyActivationData::getItems() const
{
    return items;
}
