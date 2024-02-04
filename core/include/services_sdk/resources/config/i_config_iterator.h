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

#ifndef __I_CONFIG_ITERATOR_H__
#define __I_CONFIG_ITERATOR_H__

#ifndef __CONFIG_COMPONENT_H__
#error "i_config_iterator.h should not be included directly"
#endif // __CONFIG_COMPONENT_H__

#include "maybe_res.h"

template <typename ConfigurationType>
class I_Config_Iterator
{
public:
    virtual const ConfigurationType & operator*() const = 0;
    virtual void operator++() = 0;
    virtual void operator++(int) = 0;
    virtual bool operator==(const I_Config_Iterator<ConfigurationType> &other) const = 0;
    virtual bool operator!=(const I_Config_Iterator<ConfigurationType> &other) const = 0;
    virtual std::type_index getType() const = 0;
};

#endif // __I_CONFIG_ITERATOR_H__
