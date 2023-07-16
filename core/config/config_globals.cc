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

#include "config.h"

using namespace std;
using namespace Config;

void
reportConfigurationError(const string &err)
{
    throw ConfigException(err);
}

ostream &
operator<<(ostream &os, const Errors &err)
{
    switch (err) {
        case Config::Errors::MISSING_TAG:       return os << "MISSING_TAG";
        case Config::Errors::MISSING_CONTEXT:   return os << "MISSING_CONTEXT";
        case Config::Errors::BAD_NODE:          return os << "BAD_NODE";
    }
    return os << "Unknown error";
}

void
registerConfigPrepareCb(ConfigCb cb)
{
    Singleton::Consume<I_Config>::from<MockConfigProvider>()->registerConfigPrepareCb(cb);
}

void
registerConfigLoadCb(ConfigCb cb)
{
    Singleton::Consume<I_Config>::from<MockConfigProvider>()->registerConfigLoadCb(cb);
}

void
registerConfigAbortCb(ConfigCb cb)
{
    Singleton::Consume<I_Config>::from<MockConfigProvider>()->registerConfigAbortCb(cb);
}

bool
reloadConfiguration(const std::string &version)
{
    auto res = Singleton::Consume<I_Config>::from<MockConfigProvider>()->reloadConfiguration(version, false, 0);
    return res == I_Config::AsyncLoadConfigStatus::Success;
}

string
getConfigurationFlag(const string &flag)
{
    return Singleton::Consume<I_Config>::from<MockConfigProvider>()->getConfigurationFlag(flag);
}

string
getConfigurationFlagWithDefault(const string &default_val, const string &flag)
{
    return
        Singleton::Consume<I_Config>::from<MockConfigProvider>()->getConfigurationFlagWithDefault(default_val, flag);
}

const string &
getFilesystemPathConfig()
{
    return Singleton::Consume<I_Config>::from<MockConfigProvider>()->getFilesystemPathConfig();
}

void
clearOldTenants()
{
    Singleton::Consume<I_Config>::from<MockConfigProvider>()->clearOldTenants();
}

const string &
getLogFilesPathConfig()
{
    return Singleton::Consume<I_Config>::from<MockConfigProvider>()->getLogFilesPathConfig();
}

string
getPolicyConfigPath(const string &name, ConfigFileType type, const string &tenant, const string &profile)
{
    return Singleton::Consume<I_Config>::from<MockConfigProvider>()->getPolicyConfigPath(name, type, tenant, profile);
}

void
registerExpectedConfigFile(const string &config_name, ConfigFileType type)
{
    Singleton::Consume<I_Config>::from<MockConfigProvider>()->registerExpectedConfigFile(config_name, type);
}
