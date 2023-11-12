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

#include "new_trusted_sources.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);
// LCOV_EXCL_START Reason: no test exist

static const set<string> valid_identifiers = {"headerkey", "JWTKey", "cookie", "sourceip", "x-forwarded-for"};

void
NewTrustedSourcesSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading trusted sources spec";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<int>("minNumOfSources", min_num_of_sources, archive_in, 3);
    parseAppsecJSONKey<vector<string>>("sourcesIdentifiers", sources_identifiers, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
}

void
NewTrustedSourcesSpec::setName(const string &_name)
{
    name = _name;
}

int
NewTrustedSourcesSpec::getMinNumOfSources() const
{
    return min_num_of_sources;
}

const vector<string> &
NewTrustedSourcesSpec::getSourcesIdentifiers() const
{
    return sources_identifiers;
}

const string &
NewTrustedSourcesSpec::getAppSecClassName() const
{
    return appsec_class_name;
}

const string &
NewTrustedSourcesSpec::getName() const
{
    return name;
}

void
Identifier::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading source identifiers spec";
    parseAppsecJSONKey<string>("identifier", identifier, archive_in);
    if (valid_identifiers.count(identifier) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec identifier invalid: " << identifier;
    }
    parseAppsecJSONKey<vector<string>>("value", value, archive_in);
}

const string &
Identifier::getIdentifier() const
{
    return identifier;
}

const vector<string> &
Identifier::getValues() const
{
    return value;
}

void
NewSourcesIdentifiers::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Sources Identifiers";
    parseAppsecJSONKey<string>("appsecClassName", appsec_class_name, archive_in);
    parseAppsecJSONKey<vector<Identifier>>("sourcesIdentifiers", sources_identifiers, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
}

void
NewSourcesIdentifiers::setName(const string &_name)
{
    name = _name;
}

const string &
NewSourcesIdentifiers::getName() const
{
    return name;
}

const string &
NewSourcesIdentifiers::getAppSecClassName() const
{
    return appsec_class_name;
}

const vector<Identifier> &
NewSourcesIdentifiers::getSourcesIdentifiers() const
{
    return sources_identifiers;
}
// LCOV_EXCL_STOP
