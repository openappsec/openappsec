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

#ifndef __CONFIG_LOADER_H__
#define __CONFIG_LOADER_H__

#ifndef __CONFIG_H__
#error "config_loader.h should not be included directly"
#endif // __CONFIG_H__

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#include "environment_evaluator.h"
#include "debug.h"

USE_DEBUG_FLAG(D_CONFIG);

namespace Config
{

template <typename T>
class ConfigLoader
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        try {
            readValue(ar);
        } catch (cereal::Exception &e) {
            dbgTrace(D_CONFIG) << "Failed to read value. Error: " << e.what();
            throw ConfigException(e.what());
        }
        try {
            std::string context_str;
            ar(cereal::make_nvp("context", context_str));
            if (!context_str.empty()) context = getMatcher<bool>(context_str);
        } catch (cereal::Exception &e) {
            dbgTrace(D_CONFIG) << "Failed to load. Error: " << e.what();
        }
    }

    std::pair<std::unique_ptr<EnvironmentEvaluator<bool>>, TypeWrapper>
    getLoaderConfig()
    {
        return std::move(std::make_pair(std::move(context), TypeWrapper(value)));
    }

private:
    void readValue(cereal::JSONInputArchive &ar) { value.load(ar); }

    T value;
    std::unique_ptr<EnvironmentEvaluator<bool>> context;
};

template<>
void
ConfigLoader<bool>::readValue(cereal::JSONInputArchive &ar);

template<>
void
ConfigLoader<int>::readValue(cereal::JSONInputArchive &ar);

template<>
void
ConfigLoader<uint>::readValue(cereal::JSONInputArchive &ar);

template<>
void
ConfigLoader<std::string>::readValue(cereal::JSONInputArchive &ar);

} // namespace Config

#endif // __CONFIG_LOADER_H__
