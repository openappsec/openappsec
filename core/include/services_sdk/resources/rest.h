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

#ifndef __REST_H__
#define __REST_H__
#include "cereal/archives/json.hpp"
#include "cereal/types/common.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/set.hpp"

#include <sstream>
#include <functional>

#include "debug.h"
#include "maybe_res.h"

#include "rest/schema_printer.h"

class JsonError
{
public:
    JsonError(const std::string &e) : err(e) {}
    const std::string & getMsg() const { return err; }

private:
    std::string err;
};

class BasicRest
{
    using InputFunc = std::function<void(cereal::JSONInputArchive &)>;
    using OutputFunc = std::function<void(cereal::JSONOutputArchive &)>;
    using SchemaFunc = std::function<void(std::ostream &, int)>;

public:
    enum class Direction { C2S, S2C, BOTH };
    enum class ParamType { MANDATORY, OPTIONAL, DEFAULT };

    virtual ~BasicRest() = default;

    void load(cereal::JSONInputArchive &ar)        { for (auto it : input_funcs)  it(ar); }
    void save(cereal::JSONOutputArchive &ar) const { for (auto it : output_funcs) it(ar); }

    void performOutputingSchema(std::ostream &out, int level = 0);

    template <typename RestParamType>
    void
    addSchema(const std::string &label, bool is_mandatory)
    {
        SchemaFunc func =
            [label] (std::ostream &os, int level)
            {
                SchemaPrinter<RestParamType>::print(os, level, label);
            };
        schema_func.push_back(func);
        if (is_mandatory) required.push_back(label);
    };

    template <typename RestParamType>
    void
    addInput(RestParam<RestParamType> &param, const std::string &label, ParamType type, const RestParamType &val)
    {
        InputFunc func =
            [&param, label, type, val] (cereal::JSONInputArchive &ar)
            {
                try {
                    ar(cereal::make_nvp(label, param.get()));
                    param.setActive(true);
                } catch (...) {
                    ar.setNextName(nullptr);
                    if (type == ParamType::MANDATORY) RestHelper::reportError("Couldn't get variable " + label);
                    if (type == ParamType::DEFAULT) param = val;
                }
            };
        input_funcs.push_back(func);
    }

    template <typename RestParamType>
    void
    addOutput(RestParam<RestParamType> &param, const std::string &label, ParamType type, const RestParamType &val)
    {
        OutputFunc func =
            [&param, label, type, val] (cereal::JSONOutputArchive &ar)
            {
                try {
                    if (param.isActive()) {
                        ar(cereal::make_nvp(label, param.get()));
                    } else {
                        if (type == ParamType::MANDATORY) RestHelper::reportError("Variable " + label + " isn't set");
                        if (type == ParamType::DEFAULT) ar(cereal::make_nvp(label, val));
                    }
                } catch (...) {
                    RestHelper::reportError("Couldn't output variable " + label);
                }
            };
        output_funcs.push_back(func);
    }

private:
    void outputSchema(std::ostream &os, int level);
    void outputRequired(std::ostream &os, int level);

    std::vector<InputFunc> input_funcs;
    std::vector<OutputFunc> output_funcs;
    std::vector<SchemaFunc> schema_func;
    std::vector<std::string> required;
};

class ServerRest : public BasicRest
{
public:
    virtual void doCall() = 0;

    Maybe<std::string> performRestCall(std::istream &in);

protected:
    static constexpr bool isInput(BasicRest::Direction dir)  { return dir != BasicRest::Direction::S2C; }
    static constexpr bool isOutput(BasicRest::Direction dir) { return dir != BasicRest::Direction::C2S; }
    static constexpr bool isSchema(BasicRest::Direction dir) { return dir != BasicRest::Direction::S2C; }
};

class ClientRest : public BasicRest
{
public:
    Maybe<std::string> genJson() const;
    bool loadJson(const std::string &json);

protected:
    static constexpr bool isInput(BasicRest::Direction dir)  { return dir != BasicRest::Direction::C2S; }
    static constexpr bool isOutput(BasicRest::Direction dir) { return dir != BasicRest::Direction::S2C; }
    static constexpr bool isSchema(BasicRest::Direction)     { return false; }
};


template <bool is_input>
class InputAdder
{
public:
    template <typename RestParamType>
    InputAdder(
        BasicRest *,
        RestParam<RestParamType> &,
        const std::string &,
        BasicRest::ParamType,
        const RestParamType &)
    {
    }
};

template <>
class InputAdder<true>
{
public:
    template <typename RestParamType>
    InputAdder(
        BasicRest *rest_object,
        RestParam<RestParamType> &param,
        const std::string &label,
        BasicRest::ParamType type,
        const RestParamType &val)
    {
        rest_object->addInput(param, label, type, val);
    }
};

template <bool is_output>
class OutputAdder
{
public:
    template <typename RestParamType>
    OutputAdder(
        BasicRest *,
        RestParam<RestParamType> &,
        const std::string &,
        BasicRest::ParamType,
        const RestParamType &)
    {
    }
};

template <>
class OutputAdder<true>
{
public:
    template <typename RestParamType>
    OutputAdder(
        BasicRest *rest_object,
        RestParam<RestParamType> &param,
        const std::string &label,
        BasicRest::ParamType type,
        const RestParamType &val)
    {
        rest_object->addOutput(param, label, type, val);
    }
};

template <bool is_schema, typename RestParamType>
class SchemaAdder
{
public:
    SchemaAdder(BasicRest *, const std::string &, bool)
    {
    }
};

template <typename RestParamType>
class SchemaAdder<true, RestParamType>
{
public:
    SchemaAdder(BasicRest *rest_object, const std::string &label, bool is_mandatory)
    {
        rest_object->addSchema<RestParamType>(label, is_mandatory);
    }
};

template <bool is_input, bool is_output, bool is_schema, typename RestParamType>
class AutoAdderMandatory
{
public:
    AutoAdderMandatory(BasicRest *rest_object, RestParam<RestParamType> &param, const std::string &label)
    {
        InputAdder<is_input>(rest_object, param, label, BasicRest::ParamType::MANDATORY, param.get());
        OutputAdder<is_output>(rest_object, param, label, BasicRest::ParamType::MANDATORY, param.get());
        SchemaAdder<is_schema, RestParamType>(rest_object, label, true);
    }
};

#define AUTO_ADDER_TEMPLATE(dir, type) \
    isInput(dir), isOutput(dir), isSchema(dir), type

#define ADD_MANDATORY_PARAM(dir, type, param, label) \
    RestParam<type> param;                           \
    AutoAdderMandatory<AUTO_ADDER_TEMPLATE(dir, type)> _MAN_AUTO_ADDER__##param { this, param, label };

template <bool is_input, bool is_output, bool is_schema, typename RestParamType>
class AutoAdderOptional
{
public:
    AutoAdderOptional(BasicRest *rest_object, RestParam<RestParamType> &param, const std::string &label)
    {
        InputAdder<is_input>(rest_object, param, label, BasicRest::ParamType::OPTIONAL, param.get());
        OutputAdder<is_output>(rest_object, param, label, BasicRest::ParamType::OPTIONAL, param.get());
        SchemaAdder<is_schema, RestParamType>(rest_object, label, false);
    }
};

#define ADD_OPTIONAL_PARAM(dir, type, param, label) \
    RestParam<type> param;                          \
    AutoAdderOptional<AUTO_ADDER_TEMPLATE(dir, type)> __AUTO_ADDER__##param { this, param, label };

template <bool is_input, bool is_output, bool is_schema, typename RestParamType>
class AutoAdderDefault
{
public:
    AutoAdderDefault(
        BasicRest *rest_object,
        RestParam<RestParamType> &param,
        const std::string &label,
        const RestParamType &val
    )
    {
        InputAdder<is_input>(rest_object, param, label, BasicRest::ParamType::OPTIONAL, val);
        OutputAdder<is_output>(rest_object, param, label, BasicRest::ParamType::OPTIONAL, val);
        SchemaAdder<is_schema, RestParamType>(rest_object, label, false);
    }
};

#define ADD_DEFAULT_PARAM(dir, type, param, label, val) \
    RestParam<type> param;                              \
    AutoAdderDefault<AUTO_ADDER_TEMPLATE(dir, type)>__AUTO_ADDER__##param { this, param, label, val };

template <typename N>
class ExtendableRestObject
{
public:
    ExtendableRestObject() {}
    ExtendableRestObject(std::map<std::string, N> &&_obj) : obj(std::move(_obj)) {}
    ExtendableRestObject & operator=(std::map<std::string, N> &&_obj) { obj = std::move(_obj); return *this; }
    void setElement(const std::string &name, const N &val) { obj[name] = val; }

    void
    save(cereal::JSONOutputArchive &ar) const
    {
        for (auto &iter : obj) {
            ar(cereal::make_nvp(iter.first, iter.second));
        }
    }

    void load (cereal::JSONInputArchive &) {}

private:
    std::map<std::string, N> obj;
};

#define C2S_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::C2S, type, name, label)
#define S2C_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::S2C, type, name, label)
#define BOTH_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::BOTH, type, name, label)
#define C2S_PARAM(type, name) C2S_LABEL_PARAM(type, name, #name)
#define S2C_PARAM(type, name) S2C_LABEL_PARAM(type, name, #name)
#define BOTH_PARAM(type, name) BOTH_LABEL_PARAM(type, name, #name)

#define C2S_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::C2S, type, name, label)
#define S2C_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::S2C, type, name, label)
#define BOTH_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::BOTH, type, name, label)
#define C2S_OPTIONAL_PARAM(type, name) C2S_LABEL_OPTIONAL_PARAM(type, name, #name)
#define S2C_OPTIONAL_PARAM(type, name) S2C_LABEL_OPTIONAL_PARAM(type, name, #name)
#define BOTH_OPTIONAL_PARAM(type, name) BOTH_LABEL_OPTIONAL_PARAM(type, name, #name)

#define C2S_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::C2S, type, name, label, val)
#define S2C_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::S2C, type, name, label, val)
#define BOTH_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::BOTH, type, name, label, val)
#define C2S_DEAFULT_PARAM(type, name, val) C2S_LABEL_DEAFULT_PARAM(type, name, #name, val)
#define S2C_DEAFULT_PARAM(type, name, val) S2C_LABEL_DEAFULT_PARAM(type, name, #name, val)
#define BOTH_DEAFULT_PARAM(type, name, val) BOTH_LABEL_DEAFULT_PARAM(type, name, #name, val)

#endif // __REST_H__
