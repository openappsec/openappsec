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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <string>

#include "common.h"
#include "maybe_res.h"
#include "config/config_exception.h"
#include "config/config_types.h"
#include "config/type_wrapper.h"
#include "config/config_loader.h"
#include "config/generic_config.h"
#include "config/range_config.h"
#include "config/i_config.h"

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> & getConfiguration(const Strings & ... tags);

template <typename ConfigurationType, typename ... Strings>
const ConfigurationType & getConfigurationWithDefault(const ConfigurationType &deafult_val, const Strings & ... tags);

template <typename ConfigurationType, typename ...Strings>
Config::ConfigRange<ConfigurationType> getConfigurationMultimatch(const Strings & ... tags);

template <typename ResourceType, typename ... Strings>
const Maybe<ResourceType, Config::Errors> & getResource(const Strings & ... tags);

template <typename ResourceType, typename ... Strings>
const ResourceType & getResourceWithDefault(const ResourceType &deafult_val, const Strings & ... tags);

template <typename SettingType, typename ... Strings>
const Maybe<SettingType, Config::Errors> & getSetting(const Strings & ... tags);

template <typename SettingType, typename ... Strings>
const SettingType & getSettingWithDefault(const SettingType &deafult_val, const Strings & ... tags);

template <typename SettingType>
Maybe<SettingType, Config::Errors> getProfileAgentSetting(const std::string &setting);

template <typename SettingType>
SettingType getProfileAgentSettingWithDefault(const SettingType &deafult_val, const std::string &setting);

template <typename SettingType>
Maybe<std::vector<SettingType>, Config::Errors> getProfileAgentSettingByRegex(const std::string &regex);

template <typename ConfigurationType, typename ... Strings>
bool setConfiguration(const ConfigurationType &value, const Strings & ... tags);

template <typename ResourceType, typename ... Strings>
bool setResource(const ResourceType &value, const Strings & ... tags);

template <typename SettingType, typename ... Strings>
bool setSetting(const SettingType &value, const Strings & ... tags);

template <typename ConfigurationType, typename ... Strings>
void registerExpectedConfiguration(const Strings & ... tags);

template <typename ResourceType, typename ... Strings>
void registerExpectedResource(const Strings & ... tags);

template <typename SettingType, typename ... Strings>
void registerExpectedSetting(const Strings & ... tags);

void reportConfigurationError(const std::string &err);

std::ostream & operator<<(std::ostream &os, const Config::Errors &err);

void registerConfigPrepareCb(Config::ConfigCb);
void registerConfigLoadCb(Config::ConfigCb);
void registerConfigAbortCb(Config::ConfigCb);

bool reloadConfiguration(const std::string &version = "");

std::string getConfigurationFlag(const std::string &flag);

std::string getConfigurationFlagWithDefault(const std::string &default_val, const std::string &flag_name);

const std::string & getFilesystemPathConfig();
const std::string & getLogFilesPathConfig();
void clearOldTenants();

std::string getPolicyConfigPath(
    const std::string &name,
    Config::ConfigFileType type,
    const std::string &tenant = "",
    const std::string &profile = "");

void registerExpectedConfigFile(const std::string &config_name, Config::ConfigFileType type);

#include "config/config_impl.h"

#endif // __CONFIG_H__
