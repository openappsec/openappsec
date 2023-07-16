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

#ifndef __CONFIG_IMPL_H__
#define __CONFIG_IMPL_H__

#ifndef __CONFIG_H__
#error "config_impl.h should not be included directly"
#endif // __CONFIG_H__

namespace Config
{

class MockConfigProvider : Singleton::Provide<I_Config> {};

template<typename String>
std::size_t
getParamsNumber(const String &)
{
    return 1;
}

template<typename String, typename ... Strings>
std::size_t
getParamsNumber(const String &, const Strings & ... strs)
{
    return getParamsNumber(strs ...) + 1;
}

template<typename String>
void
addStringsToVector(std::vector<std::string> &vec, const String &str)
{
    vec.emplace_back(str);
}

template<typename String, typename ... Strings>
void
addStringsToVector(std::vector<std::string> &vec, const String &str, const Strings & ... strs)
{
    vec.emplace_back(str);
    addStringsToVector(vec, strs ...);
}

template<typename ... Strings>
std::vector<std::string>
getVector(const Strings & ... strs)
{
    std::vector<std::string> res;
    res.reserve(getParamsNumber(strs ...));
    addStringsToVector(res, strs ...);
    return res;
}

} // namespace Config

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
getConfiguration(const Strings & ... strs)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->getConfiguration(Config::getVector(strs ...)).template getValue<ConfigurationType>();
};

template <typename ConfigurationType, typename ... Strings>
const ConfigurationType &
getConfigurationWithDefault(const ConfigurationType &deafult_val, const Strings & ... tags)
{
    if (!Singleton::exists<Config::I_Config>()) return deafult_val;
    auto &res = getConfiguration<ConfigurationType>(tags ...);
    return res.ok() ? res.unpack() : deafult_val;
}

template <typename ConfigurationType, typename ... Strings>
Config::ConfigRange<ConfigurationType>
getConfigurationMultimatch(const Strings & ... strs)
{
    if (!Singleton::exists<Config::I_Config>()) return Config::ConfigRange<ConfigurationType>();
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return Config::ConfigRange<ConfigurationType>(i_config->getAllConfiguration(Config::getVector(strs ...)));
}

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
getResource(const Strings & ... strs)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->getResource(Config::getVector(strs ...)).template getValue<ConfigurationType>();
};

template <typename ConfigurationType, typename ... Strings>
const ConfigurationType &
getResourceWithDefault(const ConfigurationType &deafult_val, const Strings & ... tags)
{
    if (!Singleton::exists<Config::I_Config>()) return deafult_val;
    auto &res = getResource<ConfigurationType>(tags ...);
    return res.ok() ? res.unpack() : deafult_val;
}

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
getSetting(const Strings & ... strs)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->getSetting(Config::getVector(strs ...)).template getValue<ConfigurationType>();
};

template <typename ConfigurationType, typename ... Strings>
const ConfigurationType &
getSettingWithDefault(const ConfigurationType &deafult_val, const Strings & ... tags)
{
    if (!Singleton::exists<Config::I_Config>()) return deafult_val;
    auto &res = getSetting<ConfigurationType>(tags ...);
    return res.ok() ? res.unpack() : deafult_val;
}

namespace Config
{

template <typename ProfileSettingType>
ProfileSettingType
loadProfileSetting(const std::string &val)
{
    ProfileSettingType res;
    res.load(val);
    return res;
}

template<>
bool loadProfileSetting<bool>(const std::string &val);

template<>
int loadProfileSetting<int>(const std::string &val);

template<>
uint loadProfileSetting<uint>(const std::string &val);

template<>
std::string loadProfileSetting<std::string>(const std::string &val);

} // namespace Config

template <typename SettingType>
Maybe<SettingType, Config::Errors>
getProfileAgentSetting(const std::string &setting)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    std::string value = i_config->getProfileAgentSetting(setting);

    if (value.empty()) return TypeWrapper::failMissing<SettingType>();

    try {
        return Config::loadProfileSetting<SettingType>(value);
    } catch (cereal::Exception &e) {
        dbgTrace(D_CONFIG) << "Failed to get value for setting. Setting name: " << setting << ", Error " << e.what();
    }

    return TypeWrapper::failBadNode<SettingType>();
};

template <typename SettingType>
SettingType
getProfileAgentSettingWithDefault(const SettingType &deafult_val, const std::string &setting)
{
    const auto &res = getProfileAgentSetting<SettingType>(setting);
    return res.ok() ? res.unpack() : deafult_val;
}

template <typename SettingType>
Maybe<std::vector<SettingType>, Config::Errors>
getProfileAgentSettingByRegex(const std::string &regex)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    auto values = i_config->getProfileAgentSettings(regex);

    if (values.empty()) return genError(Config::Errors::MISSING_TAG);

    std::vector<SettingType> retValues;
    retValues.reserve(values.size());
    for (auto &value: values) {
        try {
            auto retValue = Config::loadProfileSetting<SettingType>(value);
            retValues.push_back(retValue);
        } catch(const std::exception &e) {
            dbgTrace(D_CONFIG)
            << "Failed to get value for setting. Setting value: "
            << value
            << ", Error: "
            << e.what();
        }
    }
    return retValues;
}

template <typename ConfigurationType, typename ... Strings>
bool
setConfiguration(const ConfigurationType &value, const Strings & ... tags)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->setConfiguration(TypeWrapper(value), Config::getVector(tags ...));
}

template <typename ResourceType, typename ... Strings>
bool
setResource(const ResourceType &value, const Strings & ... tags)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->setResource(TypeWrapper(value), Config::getVector(tags ...));
}

template <typename SettingType, typename ... Strings>
bool
setSetting(const SettingType &value, const Strings & ... tags)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    return i_config->setSetting(TypeWrapper(value), Config::getVector(tags ...));
}

template <typename ConfigurationType, typename ... Strings>
void
registerExpectedConfiguration(const Strings & ... tags)
{
    auto conf = std::make_unique<Config::SpecificConfig<ConfigurationType, true>>(Config::getVector(tags ...));
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    i_config->registerExpectedConfiguration(std::move(conf));
}

template <typename ResourceType, typename ... Strings>
void
registerExpectedResource(const Strings & ... tags)
{
    auto conf = std::make_unique<Config::SpecificConfig<ResourceType, false>>(Config::getVector(tags ...));
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    i_config->registerExpectedResource(std::move(conf));
}

template <typename SettingType, typename ... Strings>
void
registerExpectedSetting(const Strings & ... tags)
{
    auto conf = std::make_unique<Config::SpecificConfig<SettingType, false>>(Config::getVector(tags ...));
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    i_config->registerExpectedSetting(std::move(conf));
}

#endif // __CONFIG_IMPL_H__
