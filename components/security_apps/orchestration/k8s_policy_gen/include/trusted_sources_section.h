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

#ifndef __TRUSTED_SOURCES_SECTION_H__
#define __TRUSTED_SOURCES_SECTION_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "k8s_policy_common.h"

USE_DEBUG_FLAG(D_K8S_POLICY);

class TrustedSourcesSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading trusted sources spec";
        parseAppsecJSONKey<int>("minNumOfSources", min_num_of_sources, archive_in, 3);
        parseAppsecJSONKey<std::vector<std::string>>("sourcesIdentifiers", sources_identifiers, archive_in);
    }

    int
    getMinNumOfSources() const
    {
        return min_num_of_sources;
    }

    const std::vector<std::string> &
    getSourcesIdentifiers() const
    {
        return sources_identifiers;
    }

private:
    int min_num_of_sources;
    std::vector<std::string> sources_identifiers;
};

std::ostream &
operator<<(std::ostream &os, const TrustedSourcesSpec &obj)
{
    os
        << "Min number of sources: "
        << obj.getMinNumOfSources()
        << ", SourceIdentifiers: ["
        << makeSeparatedStr(obj.getSourcesIdentifiers(), ",")
        << "]";
    return os;
}

class SourcesIdentifiers
{
public:
    SourcesIdentifiers(const std::string &_source_identifier, const std::string &_value)
            :
        source_identifier(_source_identifier),
        value(_value)
    {}

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        out_ar(
            cereal::make_nvp("sourceIdentifier",   source_identifier),
            cereal::make_nvp("value",              value)
        );
    }

    const std::string &
    getSourceIdent() const
    {
        return source_identifier;
    }

private:
    std::string source_identifier;
    std::string value;
};

class SourceIdentifierSpec
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgTrace(D_K8S_POLICY) << "Loading trusted sources spec";
        parseAppsecJSONKey<std::string>("sourceIdentifier", source_identifier, archive_in);
        parseAppsecJSONKey<std::vector<std::string>>("value", value, archive_in);
    }

    const std::string &
    getSourceIdentifier() const
    {
        return source_identifier;
    }

    const std::vector<std::string> &
    getValues() const
    {
        return value;
    }

private:
    std::string source_identifier;
    std::vector<std::string> value;
};

std::ostream &
operator<<(std::ostream &os, const SourceIdentifierSpec &obj)
{
    os
        << "sourceIdentifier: "
        << obj.getSourceIdentifier()
        << ", values: ["
        << makeSeparatedStr(obj.getValues(), ",")
        << "]";
    return os;
}

class AppSecTrustedSources
{
public:
    AppSecTrustedSources()
    {}

    AppSecTrustedSources(
        const std::string &_name,
        int _num_of_sources,
        const std::vector<SourcesIdentifiers> &_sources_identifiers)
            :
        name(_name),
        num_of_sources(_num_of_sources),
        sources_identifiers(_sources_identifiers)
    {
        try {
            id = to_string(boost::uuids::random_generator()());
        } catch (const boost::uuids::entropy_error &e) {
            dbgWarning(D_K8S_POLICY) << "Failed to generate Trusted Sources ID. Error: " << e.what();
        }
    }

    void
    save(cereal::JSONOutputArchive &out_ar) const
    {
        std::string parameter_type = "TrustedSource";
        out_ar(
            cereal::make_nvp("id",                   id),
            cereal::make_nvp("name",                 name),
            cereal::make_nvp("numOfSources",         num_of_sources),
            cereal::make_nvp("sourcesIdentifiers",   sources_identifiers),
            cereal::make_nvp("parameterType",        parameter_type)
        );
    }

    const std::vector<SourcesIdentifiers> &
    getSourcesIdentifiers() const
    {
        return sources_identifiers;
    }

private:
    std::string id;
    std::string name;
    int num_of_sources;
    std::vector<SourcesIdentifiers> sources_identifiers;
};

#endif // __TRUSTED_SOURCES_SECTION_H__
