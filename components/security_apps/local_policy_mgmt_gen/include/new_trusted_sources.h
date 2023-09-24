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

#ifndef __NEW_TRUSTED_SOURCES_H__
#define __NEW_TRUSTED_SOURCES_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "local_policy_common.h"

class NewTrustedSourcesSpec
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    int getMinNumOfSources() const;
    const std::vector<std::string> & getSourcesIdentifiers() const;
    const std::string & getAppSecClassName() const;
    const std::string & getName() const;
    void setName(const std::string &_name);

private:
    int min_num_of_sources = 0;
    std::string name;
    std::vector<std::string> sources_identifiers;
    std::string appsec_class_name;
};

class Identifier
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getIdentifier() const;
    const std::vector<std::string> & getValues() const;

private:
    std::string identifier;
    std::vector<std::string> value;
};

class NewSourcesIdentifiers
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::string & getAppSecClassName() const;
    const std::vector<Identifier> & getSourcesIdentifiers() const;
    void setName(const std::string &_name);

private:
    std::string name;
    std::string appsec_class_name;
    std::vector<Identifier> sources_identifiers;
};

#endif // __NEW_TRUSTED_SOURCES_H__
