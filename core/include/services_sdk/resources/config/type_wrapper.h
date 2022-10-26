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

#ifndef __TYPE_WRAPPER_H__
#define __TYPE_WRAPPER_H__

#ifndef __CONFIG_H__
#error "type_wrapper.h should not be included directly"
#endif // __CONFIG_H__

#include <typeinfo>
#include <typeindex>

class TypeWrapper
{
    class Value
    {
    public:
        virtual ~Value() {}
        virtual std::type_index getType() const = 0;
    };

    template <typename T>
    class SpecificValue : public Value
    {
    public:
        SpecificValue(const T &_val) : val(_val) {}

        std::type_index getType() const override { return typeid(T); }

        const Maybe<T, Config::Errors> val;
        static Maybe<T, Config::Errors> missing_tag;
        static Maybe<T, Config::Errors> bad_node;
    };

public:
    TypeWrapper() {}

    template <typename T>
    TypeWrapper(const T &val) : p_val(std::make_shared<SpecificValue<T>>(val)) {}

    template <typename T>
    const Maybe<T, Config::Errors> &
    getValue() const
    {
        if (!p_val) return SpecificValue<T>::missing_tag;
        if (p_val->getType() != typeid(T)) return SpecificValue<T>::bad_node;
        return static_cast<SpecificValue<T> *>(p_val.get())->val;
    }

    template <typename T>
    static const Maybe<T, Config::Errors> & failMissing() { return SpecificValue<T>::missing_tag; }

    template <typename T>
    static const Maybe<T, Config::Errors> & failBadNode() { return SpecificValue<T>::bad_node; }

    bool ok() { return p_val != nullptr; }

private:
    std::shared_ptr<Value> p_val = nullptr;
};

template <typename T>
Maybe<T, Config::Errors> TypeWrapper::SpecificValue<T>::missing_tag{genError(Config::Errors::MISSING_TAG)};

template <typename T>
Maybe<T, Config::Errors> TypeWrapper::SpecificValue<T>::bad_node{genError(Config::Errors::BAD_NODE)};

#endif // __TYPE_WRAPPER_H__
