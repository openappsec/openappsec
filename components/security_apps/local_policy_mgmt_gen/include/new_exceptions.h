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

#ifndef __NEW_EXCEPTIONS_H__
#define __NEW_EXCEPTIONS_H__

#include <string>
#include <cereal/archives/json.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "config.h"
#include "debug.h"
#include "rest.h"
#include "local_policy_common.h"

class NewAppsecExceptionCondition
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getKey() const;
    const std::string & getvalue() const;

private:
    std::string key;
    std::string value;
};

class NewAppsecException
{
public:
    void load(cereal::JSONInputArchive &archive_in);

    const std::string & getName() const;
    const std::string & getAction() const;
    const std::string & getAppSecClassName() const;
    const std::vector<std::string> getCountryCode() const;
    const std::vector<std::string> getCountryName() const;
    const std::vector<std::string> getHostName() const;
    const std::vector<std::string> getParamName() const;
    const std::vector<std::string> getParamValue() const;
    const std::vector<std::string> getProtectionName() const;
    const std::vector<std::string> getSourceIdentifier() const;
    const std::vector<std::string> getSourceIp() const;
    const std::vector<std::string> getUrl() const;
    void setName(const std::string &_name);

private:
    std::string appsec_class_name;
    std::string name;
    std::string action;
    std::vector<NewAppsecExceptionCondition> conditions;
};

#endif // __NEW_EXCEPTIONS_H__
