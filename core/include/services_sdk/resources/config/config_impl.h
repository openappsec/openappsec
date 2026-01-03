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

#include <fstream>
#include <unistd.h>
#include <atomic>
#include <cstdlib>
#include <algorithm>
#include <cctype>

namespace Config
{
class MockConfigProvider
        :
    public Singleton::Provide<I_Config>,
    public Singleton::Consume<I_Environment>
{};

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

// Utility function to create a separated string from a vector
inline std::string
makeSeparatedStr(const std::vector<std::string> &vec, const std::string &separator = ", ")
{
    if (vec.empty()) return "";
    if (vec.size() == 1) return vec[0];

    std::string result = vec[0];
    for (size_t i = 1; i < vec.size(); ++i) {
        result += separator + vec[i];
    }
    return result;
}

} // namespace Config

// Efficient service type checking for caching
inline bool isHttpTransactionHandler() {
    static bool is_http_transaction_handler = false;
    static bool service_checked = false;

    if (!service_checked) {
        auto i_environment = Singleton::Consume<I_Environment>::by<Config::MockConfigProvider>();
        if (i_environment != nullptr) {
            auto maybe_service_name = i_environment->get<std::string>("Service Name");
            if (maybe_service_name.ok()) {
                is_http_transaction_handler = (maybe_service_name.unpack() == "HTTP Transaction Handler");
                service_checked = true;
            }
        }
    }
    return is_http_transaction_handler;
}

// Context registration for cache-enabled configurations
template <typename ConfigurationType>
struct ContextRegistration {
    static std::map<std::vector<std::string>, std::string> path_to_context_map;

    static void registerContext(const std::vector<std::string>& paths, const std::string& context_type) {
        path_to_context_map[paths] = context_type;
    }

    static std::string getContext(const std::vector<std::string>& paths) {
        auto it = path_to_context_map.find(paths);
        return (it != path_to_context_map.end()) ? it->second : "";
    }
};

// Static member definition
template <typename ConfigurationType>
std::map<std::vector<std::string>, std::string> ContextRegistration<ConfigurationType>::path_to_context_map;

template <typename ConfigurationType>
struct ConfigCacheKey {
    std::vector<std::string> paths;
    std::string context_value;
    std::string policy_load_id;

    bool operator==(const ConfigCacheKey &other) const
    {
        return paths == other.paths &&
            context_value == other.context_value &&
            policy_load_id == other.policy_load_id;
    }

    bool match(
        const std::vector<std::string>& other_paths,
        const std::string& other_context_value,
        const std::string& other_policy_load_id
    ) const
    {
        return paths == other_paths &&
                context_value == other_context_value &&
                policy_load_id == other_policy_load_id;
    }
};

template <typename ConfigurationType>
struct ConfigCacheEntry {
    ConfigCacheKey<ConfigurationType> key;
    Maybe<ConfigurationType, Config::Errors> value;
    ConfigCacheEntry()
        : key(), value(genError(Config::Errors::MISSING_TAG)) {}

    bool isValid() const { return !key.context_value.empty(); }
    void invalidate()
    {
        key.context_value.clear();
        value = genError(Config::Errors::MISSING_TAG);
    }
};


template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
getConfiguration(const Strings & ... strs)
{
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    const auto &paths = Config::getVector(strs ...);

    return i_config->getConfiguration(paths).template getValue<ConfigurationType>();
};

// LCOV_EXCL_START - Helper function to isolate static variables from lcov function data mismatch
// Helper function to get cache array - isolates static variables
template <typename ConfigurationType>
ConfigCacheEntry<ConfigurationType>* getCacheArray() {
    static ConfigCacheEntry<ConfigurationType> config_cache[3];
    return config_cache;
}

// Cache statistics tracking
struct CacheStats {
    static std::atomic<uint64_t> hits;
    static std::atomic<uint64_t> misses;
    static bool tracking_enabled;

    static void recordHit() {
        if (tracking_enabled) hits.fetch_add(1, std::memory_order_relaxed);
    }

    static void recordMiss() {
        if (tracking_enabled) misses.fetch_add(1, std::memory_order_relaxed);
    }

    static uint64_t getHits() { return hits.load(std::memory_order_relaxed); }
    static uint64_t getMisses() { return misses.load(std::memory_order_relaxed); }

    static void reset() {
        hits.store(0, std::memory_order_relaxed);
        misses.store(0, std::memory_order_relaxed);
    }

    static void enableTracking() { tracking_enabled = true; }
    static void disableTracking() { tracking_enabled = false; }
    static bool isTrackingEnabled() { return tracking_enabled; }
};

// Initialize cache tracking from environment variable
inline void initializeCacheTracking() {
    const char* enable_tracking = std::getenv("ENABLE_CONFIG_CACHE_TRACKING");
    if (enable_tracking != nullptr) {
        // Check for various "true" values
        std::string tracking_value(enable_tracking);
        std::transform(tracking_value.begin(), tracking_value.end(), tracking_value.begin(), ::tolower);
        if (tracking_value == "true") {
            CacheStats::enableTracking();
            CacheStats::reset(); // Start with clean counters when enabling tracking
        }
    }
}
// LCOV_EXCL_STOP

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
getConfigurationWithCache(const Strings & ... strs)
{
    // Step 1: Check if current service is HTTP Transaction Handler
    if (!isHttpTransactionHandler()) {
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 2: Fast checks - get basic info
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    const auto &paths = Config::getVector(strs ...);
    size_t idx = paths.size();

    // Step 3: Quick validation checks (fastest)
    bool idx_valid = (idx >= 1 && idx <= 3); // max_cache_key_size = 3
    if (!idx_valid || !i_config->isConfigCacheEnabled()) {
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 4: Single map lookup - get context if registered, empty string if not
    std::string context_type = ContextRegistration<ConfigurationType>::getContext(paths);
    if (context_type.empty()) {
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 5: Now we know it's registered - get environment value using the context
    std::string context_value;
    auto i_environment = Singleton::Consume<I_Environment>::by<Config::MockConfigProvider>();
    if (i_environment != nullptr) {
        auto maybe_context_value = i_environment->get<std::string>(
            (context_type == "triggerId") ? "triggers" : "asset_id");
        if (maybe_context_value.ok()) {
            context_value = maybe_context_value.unpack();
        }
    }

    // Step 6: Final cache enablement check
    if (context_value.empty()) {
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 7: Cache operations
    auto* config_cache = getCacheArray<ConfigurationType>();
    std::string policy_load_id = i_config->getPolicyLoadId();

    // Check cache first
    ConfigCacheEntry<ConfigurationType> &entry = config_cache[idx - 1];
    if (entry.key.match(paths, context_value, policy_load_id)) {
        // Cache hit
        CacheStats::recordHit();
        return entry.value;
    }

    // Cache miss - get configuration and update cache
    CacheStats::recordMiss();
    const auto &maybe_val = i_config->getConfiguration(paths).template getValue<ConfigurationType>();

    // Update cache
    config_cache[idx - 1].key = ConfigCacheKey<ConfigurationType>{paths, context_value, policy_load_id};
    config_cache[idx - 1].value = maybe_val;

    return maybe_val;
}

template <typename ConfigurationType, typename ... Strings>
const Maybe<ConfigurationType, Config::Errors> &
setConfigurationInCache(const Strings & ... strs)
{
    // Step 1: Check if current service is HTTP Transaction Handler
    if (!isHttpTransactionHandler()) {
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 2: Fast checks - get basic info
    auto i_config = Singleton::Consume<Config::I_Config>::from<Config::MockConfigProvider>();
    const auto &paths = Config::getVector(strs ...);
    size_t idx = paths.size();

    // Step 3: Quick validation checks (fastest)
    bool idx_valid = (idx >= 1 && idx <= 3); // max_cache_key_size = 3
    if (!idx_valid || !i_config->isConfigCacheEnabled()) {
        // Early exit - no caching possible, just fetch and return
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 4: Single map lookup - get context if registered, empty string if not
    std::string context_type = ContextRegistration<ConfigurationType>::getContext(paths);
    if (context_type.empty()) {
        // Not registered for caching - just fetch and return
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 5: Now we know it's registered - get environment value using the context
    std::string context_value;
    auto i_environment = Singleton::Consume<I_Environment>::by<Config::MockConfigProvider>();
    if (i_environment != nullptr) {
        auto maybe_context_value = i_environment->get<std::string>(
            (context_type == "triggerId") ? "triggers" : "asset_id");
        if (maybe_context_value.ok()) {
            context_value = maybe_context_value.unpack();
        }
    }

    // Step 6: Final cache enablement check
    if (context_value.empty()) {
        // No valid context value - just fetch and return
        return getConfiguration<ConfigurationType>(strs...);
    }

    // Step 7: Always fetch configuration and update cache (no cache check first)
    auto* config_cache = getCacheArray<ConfigurationType>();
    std::string policy_load_id = i_config->getPolicyLoadId();

    // Fetch configuration directly - no cache hit check
    const auto &maybe_val = i_config->getConfiguration(paths).template getValue<ConfigurationType>();

    // Update cache with fresh value
    config_cache[idx - 1].key = ConfigCacheKey<ConfigurationType>{paths, context_value, policy_load_id};
    config_cache[idx - 1].value = maybe_val;

    return maybe_val;
}

template <typename ConfigurationType, typename ... Strings>
const ConfigurationType &
getConfigurationWithDefault(const ConfigurationType &deafult_val, const Strings & ... tags)
{
    if (!Singleton::exists<Config::I_Config>()) return deafult_val;
    auto &res = getConfigurationWithCache<ConfigurationType>(tags ...);
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

template <typename ConfigurationType, typename ... Strings>
void
registerExpectedConfigurationWithCache(const std::string& context_type, const Strings & ... tags)
{
    // Register with the original system using existing function
    registerExpectedConfiguration<ConfigurationType>(tags...);

    // Register the context mapping
    const auto &paths = Config::getVector(tags ...);
    ContextRegistration<ConfigurationType>::registerContext(paths, context_type);
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

