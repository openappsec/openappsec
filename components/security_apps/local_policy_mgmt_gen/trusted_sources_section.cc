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

#include "policy_maker_utils.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static const set<string> valid_source_identifiers = {"headerkey", "JWTKey", "cookie", "sourceip", "x-forwarded-for"};

void
TrustedSourcesSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading trusted sources spec";
    parseAppsecJSONKey<int>("minNumOfSources", min_num_of_sources, archive_in, 3);
    parseAppsecJSONKey<vector<string>>("sourcesIdentifiers", sources_identifiers, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
}

void
TrustedSourcesSpec::setName(const string &_name)
{
    name = _name;
}

int
TrustedSourcesSpec::getMinNumOfSources() const
{
    return min_num_of_sources;
}

const vector<string> &
TrustedSourcesSpec::getSourcesIdentifiers() const
{
    return sources_identifiers;
}

const string &
TrustedSourcesSpec::getName() const
{
    return name;
}

void
SourcesIdentifiers::save(cereal::JSONOutputArchive &out_ar) const
{
    out_ar(
        cereal::make_nvp("sourceIdentifier",   source_identifier),
        cereal::make_nvp("value",              value)
    );
}

const string &
SourcesIdentifiers::getSourceIdent() const
{
    return source_identifier;
}

void
SourceIdentifierSpec::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading source identifiers spec";
    parseAppsecJSONKey<string>("sourceIdentifier", source_identifier, archive_in);
    if (valid_source_identifiers.count(source_identifier) == 0) {
        dbgWarning(D_LOCAL_POLICY) << "AppSec source identifier invalid: " << source_identifier;
    }
    parseAppsecJSONKey<vector<string>>("value", value, archive_in);
}

const string &
SourceIdentifierSpec::getSourceIdentifier() const
{
    return source_identifier;
}

const vector<string> &
SourceIdentifierSpec::getValues() const
{
    return value;
}

void
SourceIdentifierSpecWrapper::load(cereal::JSONInputArchive &archive_in)
{
    dbgTrace(D_LOCAL_POLICY) << "Loading Source Identifier Spec Wrapper";
    parseAppsecJSONKey<vector<SourceIdentifierSpec>>("identifiers", identifiers, archive_in);
    parseAppsecJSONKey<string>("name", name, archive_in);
}

void
SourceIdentifierSpecWrapper::setName(const string &_name)
{
    name = _name;
}

const string &
SourceIdentifierSpecWrapper::getName() const
{
    return name;
}

const vector<SourceIdentifierSpec> &
SourceIdentifierSpecWrapper::getIdentifiers() const
{
    return identifiers;
}

AppSecTrustedSources::AppSecTrustedSources(
    const string &_name,
    int _num_of_sources,
    const vector<SourcesIdentifiers> &_sources_identifiers)
        :
    name(_name),
    num_of_sources(_num_of_sources),
    sources_identifiers(_sources_identifiers)
{
    try {
        id = to_string(boost::uuids::random_generator()());
    } catch (const boost::uuids::entropy_error &e) {
        dbgWarning(D_LOCAL_POLICY) << "Failed to generate Trusted Sources ID. Error: " << e.what();
    }
}

void
AppSecTrustedSources::save(cereal::JSONOutputArchive &out_ar) const
{
    string parameter_type = "TrustedSource";
    out_ar(
        cereal::make_nvp("id",                   id),
        cereal::make_nvp("name",                 name),
        cereal::make_nvp("numOfSources",         num_of_sources),
        cereal::make_nvp("sourcesIdentifiers",   sources_identifiers),
        cereal::make_nvp("parameterType",        parameter_type)
    );
}

const vector<SourcesIdentifiers> &
AppSecTrustedSources::getSourcesIdentifiers() const
{
    return sources_identifiers;
}
