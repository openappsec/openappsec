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
#include "local_policy_common.h"

class TrustedSourcesSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getMinNumOfSources() const;
    const std::vector<std::string> & getSourcesIdentifiers() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    int min_num_of_sources = 0;
    std::string name;
    std::vector<std::string> sources_identifiers;
};

class SourcesIdentifiers
{
public:
    SourcesIdentifiers(const std::string &_source_identifier, const std::string &_value)
            :
        source_identifier(_source_identifier),
        value(_value)
    {}

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::string & getSourceIdent() const;

private:
    std::string source_identifier;
    std::string value;
};

class SourceIdentifierSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getSourceIdentifier() const;
    const std::vector<std::string> & getValues() const;

private:
    std::string source_identifier;
    std::vector<std::string> value;
};

class SourceIdentifierSpecWrapper
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::vector<SourceIdentifierSpec> & getIdentifiers() const;
    void setName(const std::string &_name);

private:
    std::string name;
    std::vector<SourceIdentifierSpec> identifiers;
};

class AppSecTrustedSources
{
public:
    AppSecTrustedSources()
    {}

    AppSecTrustedSources(
        const std::string &_name,
        int _num_of_sources,
        const std::vector<SourcesIdentifiers> &_sources_identifiers
    );

    void save(cereal::JSONOutputArchive &out_ar) const;
    const std::vector<SourcesIdentifiers> & getSourcesIdentifiers() const;

private:
    std::string id;
    std::string name;
    int num_of_sources = 0;
    std::vector<SourcesIdentifiers> sources_identifiers;
};
#endif // __TRUSTED_SOURCES_SECTION_H__
