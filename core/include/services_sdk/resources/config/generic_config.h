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

#ifndef __GENERIC_CONFIG_H__
#define __GENERIC_CONFIG_H___

#ifndef __CONFIG_H__
#error "generic_config.h should not be included directly"
#endif // __CONFIG_H__

namespace Config
{

template <bool IsPerContext>
struct ConfigTypesBasic
{
    using ReturnType = TypeWrapper;
};

template <typename T, bool IsPerContext>
struct ConfigTypes : ConfigTypesBasic<IsPerContext>
{
    using LoadType = T;

    static typename ConfigTypesBasic<IsPerContext>::ReturnType
    convetLoadToReturn(const LoadType &val)
    {
        return typename ConfigTypesBasic<IsPerContext>::ReturnType(val);
    }
};

template <>
struct ConfigTypesBasic<true>
{
    using ReturnType = std::vector<std::pair<std::shared_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>>;
};

template <typename T>
struct ConfigTypes<T, true> : ConfigTypesBasic<true>
{
    using LoadType = std::vector<ConfigLoader<T>>;
    static typename ConfigTypesBasic<true>::ReturnType
    convetLoadToReturn(LoadType &val)
    {
        ReturnType res;
        res.reserve(val.size());

        for (auto &entry : val) {
            res.emplace_back(std::move(entry.getLoaderConfig()));
        }

        return res;
    }
};

template <bool IsPerContext>
class GenericConfig
{
public:
    GenericConfig(const std::vector<std::string> &_path) : path(_path) {}

    const std::vector<std::string> & getPath() const { return path; }

    typename ConfigTypesBasic<IsPerContext>::ReturnType
    loadConfiguration(cereal::JSONInputArchive &ar)
    {
        res = typename ConfigTypesBasic<IsPerContext>::ReturnType();
        iter = path.begin();
        try {
            load(ar);
        } catch (cereal::Exception &e) {
            dbgTrace(D_CONFIG) << "Failed to load generic configuration. Error: " << e.what();
        }
        return res;
    }

    void
    load(cereal::JSONInputArchive &ar)
    {
        const std::string &curr_tag = *iter;
        iter++;
        if (iter == path.end()) {
            loadContextArray(ar, curr_tag);
        } else {
            ar(cereal::make_nvp(curr_tag, *this));
        }
    }

    virtual void loadContextArray(cereal::JSONInputArchive &ar, const std::string &curr_tag) = 0;

protected:
    std::vector<std::string> path;
    std::vector<std::string>::iterator iter;
    typename ConfigTypesBasic<IsPerContext>::ReturnType res;
};

template <typename T, bool IsPerContext>
class SpecificConfig : public GenericConfig<IsPerContext>
{
public:
    SpecificConfig(const std::vector<std::string> &_path) : GenericConfig<IsPerContext>(_path) {}

    void
    loadContextArray(cereal::JSONInputArchive &ar, const std::string &curr_tag) override
    {
        typename ConfigTypes<T, IsPerContext>::LoadType load;

        try {
            ar(cereal::make_nvp(curr_tag, load));
            GenericConfig<IsPerContext>::res = std::move(ConfigTypes<T, IsPerContext>::convetLoadToReturn(load));
        } catch (cereal::Exception &e) {
            if (e.what() == "JSON Parsing failed - provided NVP (" + curr_tag + ") not found") {
                dbgTrace(D_CONFIG) << "Failed to load specific configuration. Error: " << e.what();
                return;
            }
            dbgTrace(D_CONFIG) << "Failed to load specific configuration. Error: " << e.what();
            throw ConfigException(e.what());
        }
    }
};

} // namespace Config

#endif // __GENERIC_CONFIG_H__
