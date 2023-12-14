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

#include "new_exceptions.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

// LCOV_EXCL_START Reason: no test exist
static const set<string> valid_actions = {"skip", "accept", "drop", "suppressLog"};

void
NewAppsecExceptionCondition::load(cereal::JSONInputArchive &archive_in)
{
    parseAppsecJSONKey<string>("key", key, archive_in);
    parseAppsecJSONKey<string>("value", value, archive_in);
    dbgTrace(D_LOCAL_POLICY) << "Key: " << key << " Value: " << value;
}

const string &
NewAppsecExceptionCondition::getKey() const
{
    return key;
}

const string &
NewAppsecExceptionCondition::getvalue() const
{
    return value;
}

void
NewAppsecException::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading New AppSec exception";
    parseAppsecJSONKey<string>("name", name, archive_in, "exception");
    parseAppsecJSONKey<string>("action", action, archive_in);
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    if (valid_actions.count(action) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec exception action invalid: " << action;
    }
    parseAppsecJSONKey<vector<NewAppsecExceptionCondition>>("condition", conditions, archive_in);
}

void
NewAppsecException::setName(const string &_name)
{
    name = _name;
}

const string &
NewAppsecException::getName() const
{
    return name;
}

const string &
NewAppsecException::getAction() const
{
    return action;
}

const string &
NewAppsecException::getAppSecClassName() const
{
    return appsec_class_name;
}

const vector<string>
NewAppsecException::getCountryCode() const
{
    vector<string> country_codes;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "countryCode") {
            country_codes.push_back(condition.getvalue());
        }
    }
    return country_codes;
}

const vector<string>
NewAppsecException::getCountryName() const
{
    vector<string> country_names;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "countryName") {
            country_names.push_back(condition.getvalue());
        }
    }
    return country_names;
}

const vector<string>
NewAppsecException::getHostName() const
{
    vector<string> host_names;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "hostName") {
            host_names.push_back(condition.getvalue());
        }
    }
    return host_names;
}

const vector<string>
NewAppsecException::getParamName() const
{
    vector<string> param_names;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "paramName") {
            param_names.push_back(condition.getvalue());
        }
    }
    return param_names;
}

const vector<string>
NewAppsecException::getParamValue() const
{
    vector<string> param_values;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "paramValue") {
            param_values.push_back(condition.getvalue());
        }
    }
    return param_values;
}

const vector<string>
NewAppsecException::getProtectionName() const
{
    vector<string> protection_names;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "protectionName") {
            protection_names.push_back(condition.getvalue());
        }
    }
    return protection_names;
}

const vector<string>
NewAppsecException::getSourceIdentifier() const
{
    vector<string> source_identifiers;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "sourceIdentifier") {
            source_identifiers.push_back(condition.getvalue());
        }
    }
    return source_identifiers;
}

const vector<string>
NewAppsecException::getSourceIp() const
{
    vector<string> source_ips;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "sourceIp") {
            source_ips.push_back(condition.getvalue());
        }
    }
    return source_ips;
}

const vector<string>
NewAppsecException::getUrl() const
{
    vector<string> urls;
    for (const NewAppsecExceptionCondition &condition : conditions) {
        if (condition.getKey() == "url") {
            urls.push_back(condition.getvalue());
        }
    }
    return urls;
}
// LCOV_EXCL_STOP
