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

/// @file rest.h
/// @brief Header file for RESTful communication functionalities.
///
/// This file defines classes and utilities for RESTful communication, including input/output handling,
/// schema generation, and client-server interactions.

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

/// @class JsonError
/// @brief Class representing JSON parsing errors.
///
/// This class is used to represent errors that occur during JSON parsing.
class JsonError
{
public:
    /// @brief Constructor for JsonError class.
    /// @param e The error message to be stored.
    JsonError(const std::string &e) : err(e) {}

    /// @brief Retrieves the error message.
    /// @return The error message as a constant reference to a string.
    const std::string &getMsg() const { return err; }

private:
    std::string err; ///< Error message.
};

/// @class BasicRest
/// @brief Base class for RESTful communication handling.
///
/// The BasicRest class provides basic functionalities for handling RESTful communication,
/// including input/output handling, schema generation, and client-server interactions.
class BasicRest
{
    using InputFunc = std::function<void(cereal::JSONInputArchive &)>;
    using OutputFunc = std::function<void(cereal::JSONOutputArchive &)>;
    using SchemaFunc = std::function<void(std::ostream &, int)>;

public:
    /// @brief Enumeration representing the direction of communication (Client to Server, Server to Client, or Both).
    enum class Direction { C2S, S2C, BOTH };

    /// @brief Enumeration representing the type of parameter (Mandatory, Optional, or Default).
    enum class ParamType { MANDATORY, OPTIONAL, DEFAULT };

    /// @brief Destructor for the BasicRest class.
    virtual ~BasicRest() = default;

    /// @brief Loads data from the JSON input archive.
    /// @param ar The JSON input archive.
    void load(cereal::JSONInputArchive &ar) { for (auto it : input_funcs)  it(ar); }

    /// @brief Saves data to the JSON output archive.
    /// @param ar The JSON output archive.
    void save(cereal::JSONOutputArchive &ar) const { for (auto it : output_funcs) it(ar); }

    /// @brief Outputs the schema to an output stream.
    /// @param out The output stream to write the schema to.
    /// @param level The indentation level for the schema.
    void performOutputingSchema(std::ostream &out, int level = 0);

    /// @brief Adds a schema for the given REST parameter type.
    /// @tparam RestParamType The type of the REST parameter.
    /// @param label The label for the parameter in the schema.
    /// @param is_mandatory A boolean indicating whether the parameter is mandatory in the schema.
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

    /// @brief Adds an input parameter of the given REST parameter type.
    /// @tparam RestParamType The type of the REST parameter.
    /// @param param The REST parameter to add as an input.
    /// @param label The label for the parameter in the input.
    /// @param type The parameter type (Mandatory, Optional, or Default).
    /// @param val The default value for the parameter (used for default parameters).
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

    /// @brief Adds an output parameter of the given REST parameter type.
    /// @tparam RestParamType The type of the REST parameter.
    /// @param param The REST parameter to add as an output.
    /// @param label The label for the parameter in the output.
    /// @param type The parameter type (Mandatory, Optional, or Default).
    /// @param val The default value for the parameter (used for default parameters).
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

    std::vector<InputFunc> input_funcs;  ///< Vector storing input functions.
    std::vector<OutputFunc> output_funcs; ///< Vector storing output functions.
    std::vector<SchemaFunc> schema_func;  ///< Vector storing schema functions.
    std::vector<std::string> required;    ///< Vector storing the names of required parameters.
};

/// @class ServerRest
/// @brief Class representing a server-side RESTful communication handler.
///
/// The ServerRest class is used for server-side RESTful communication and provides
/// functionality for handling REST calls.
class ServerRest : public BasicRest
{
public:
    /// @brief Virtual function for handling a REST call.
    virtual void doCall() = 0;

    /// @brief Performs the REST call using the input stream.
    /// @param in The input stream containing the JSON data for the REST call.
    /// @return A Maybe object containing the result of the REST call (either the JSON data or an error message).
    Maybe<std::string> performRestCall(std::istream &in);

protected:
    /// @brief Determines if the direction is for input.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for input, false otherwise.
    static constexpr bool isInput(BasicRest::Direction dir) { return dir != BasicRest::Direction::S2C; }

    /// @brief Determines if the direction is for output.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for output, false otherwise.
    static constexpr bool isOutput(BasicRest::Direction dir) { return dir != BasicRest::Direction::C2S; }

    /// @brief Determines if the direction is for schema.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for schema, false otherwise.
    static constexpr bool isSchema(BasicRest::Direction dir) { return dir != BasicRest::Direction::S2C; }
};

/// @class ClientRest
/// @brief Class representing a client-side RESTful communication handler.
///
/// The ClientRest class is used for client-side RESTful communication and provides
/// functionality for generating and loading JSON data.
class ClientRest : public BasicRest
{
public:
    /// @brief Generates JSON data from the object's state.
    /// @return A Maybe object containing the JSON data, or an error message if serialization fails.
    Maybe<std::string> genJson() const;

    /// @brief Loads JSON data into the object's state.
    /// @param json The JSON data to be loaded.
    /// @return True if the JSON data is successfully loaded, false otherwise.
    bool loadJson(const std::string &json);

protected:
    /// @brief Determines if the direction is for input.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for input, false otherwise.
    static constexpr bool isInput(BasicRest::Direction dir) { return dir != BasicRest::Direction::C2S; }

    /// @brief Determines if the direction is for output.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for output, false otherwise.
    static constexpr bool isOutput(BasicRest::Direction dir) { return dir != BasicRest::Direction::S2C; }

    /// @brief Determines if the direction is for schema.
    /// @param dir The direction of the communication.
    /// @return True if the direction is for schema, false otherwise.
    static constexpr bool isSchema(BasicRest::Direction) { return false; }
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

/// @def C2S_LABEL_PARAM(type, name, label)
/// @brief Add a mandatory parameter for the Client-to-Server (C2S) direction.
///
/// This macro is used to add a mandatory parameter to a REST request sent from
/// the client to the server.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define C2S_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::C2S, type, name, label)

/// @def S2C_LABEL_PARAM(type, name, label)
/// @brief Add a mandatory parameter for the Server-to-Client (S2C) direction.
///
/// This macro is used to add a mandatory parameter to a REST response sent from
/// the server to the client.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define S2C_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::S2C, type, name, label)

/// @def BOTH_LABEL_PARAM(type, name, label)
/// @brief Add a mandatory parameter for both Client-to-Server (C2S) and Server-to-Client (S2C) directions.
///
/// This macro is used to add a mandatory parameter that is used in both the request
/// and response of a REST communication.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define BOTH_LABEL_PARAM(type, name, label) \
    ADD_MANDATORY_PARAM(BasicRest::Direction::BOTH, type, name, label)

/// @def C2S_PARAM(type, name)
/// @brief Add a mandatory parameter for the Client-to-Server (C2S) direction with the parameter
/// label being the same as the parameter name.
///
/// This macro is a shorthand for adding a mandatory parameter to a REST request with
/// the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define C2S_PARAM(type, name) C2S_LABEL_PARAM(type, name, #name)

/// @def S2C_PARAM(type, name)
/// @brief Add a mandatory parameter for the Server-to-Client (S2C) direction with the parameter
/// label being the same as the parameter name.
///
/// This macro is a shorthand for adding a mandatory parameter to a REST response with
/// the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define S2C_PARAM(type, name) S2C_LABEL_PARAM(type, name, #name)

/// @def BOTH_PARAM(type, name)
/// @brief Add a mandatory parameter for both Client-to-Server (C2S) and Server-to-Client (S2C) directions
/// with the parameter label being the same as the parameter name.
///
/// This macro is a shorthand for adding a mandatory parameter that is used in both the
/// request and response of a REST communication with the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define BOTH_PARAM(type, name) BOTH_LABEL_PARAM(type, name, #name)

/// @def C2S_LABEL_OPTIONAL_PARAM(type, name, label)
/// @brief Add an optional parameter for the Client-to-Server (C2S) direction.
///
/// This macro is used to add an optional parameter to a REST request sent from the client
/// to the server.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define C2S_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::C2S, type, name, label)

/// @def S2C_LABEL_OPTIONAL_PARAM(type, name, label)
/// @brief Add an optional parameter for the Server-to-Client (S2C) direction.
///
/// This macro is used to add an optional parameter to a REST response sent from the server
/// to the client.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define S2C_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::S2C, type, name, label)

/// @def BOTH_LABEL_OPTIONAL_PARAM(type, name, label)
/// @brief Add an optional parameter for both Client-to-Server (C2S) and Server-to-Client (S2C) directions.
///
/// This macro is used to add an optional parameter that can be used in both the request
/// and response of a REST communication.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
#define BOTH_LABEL_OPTIONAL_PARAM(type, name, label) \
    ADD_OPTIONAL_PARAM(BasicRest::Direction::BOTH, type, name, label)

/// @def C2S_OPTIONAL_PARAM(type, name)
/// @brief Add an optional parameter for the Client-to-Server (C2S) direction with the parameter label
/// being the same as the parameter name.
///
/// This macro is a shorthand for adding an optional parameter to a REST request with
/// the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define C2S_OPTIONAL_PARAM(type, name) C2S_LABEL_OPTIONAL_PARAM(type, name, #name)

/// @def S2C_OPTIONAL_PARAM(type, name)
/// @brief Add an optional parameter for the Server-to-Client (S2C) direction with the parameter label
/// being the same as the parameter name.
///
/// This macro is a shorthand for adding an optional parameter to a REST response with
/// the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define S2C_OPTIONAL_PARAM(type, name) S2C_LABEL_OPTIONAL_PARAM(type, name, #name)

/// @def BOTH_OPTIONAL_PARAM(type, name)
/// @brief Add an optional parameter for both Client-to-Server (C2S) and Server-to-Client (S2C) directions
/// with the parameter label being the same as the parameter name.
///
/// This macro is a shorthand for adding an optional parameter that can be used in both the
/// request and response of a REST communication with the same label as the parameter name.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
#define BOTH_OPTIONAL_PARAM(type, name) BOTH_LABEL_OPTIONAL_PARAM(type, name, #name)

/// @def C2S_LABEL_DEAFULT_PARAM(type, name, label, val)
/// @brief Add a parameter with a default value for the Client-to-Server (C2S) direction.
///
/// This macro is used to add a parameter to a REST request with a default value. If the
/// parameter is not provided in the request, the default value will be used.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
/// @param val The default value of the parameter.
#define C2S_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::C2S, type, name, label, val)

/// @def S2C_LABEL_DEAFULT_PARAM(type, name, label, val)
/// @brief Add a parameter with a default value for the Server-to-Client (S2C) direction.
///
/// This macro is used to add a parameter to a REST response with a default value. If the
/// parameter is not provided in the response, the default value will be used.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
/// @param val The default value of the parameter.
#define S2C_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::S2C, type, name, label, val)

/// @def BOTH_LABEL_DEAFULT_PARAM(type, name, label, val)
/// @brief Add a parameter with a default value for both Client-to-Server (C2S) and Server-to-Client (S2C) directions.
///
/// This macro is used to add a parameter to a REST response with a default value. If the
/// parameter is not provided in the response, the default value will be used.
///
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param label The label or name of the parameter as it appears in the JSON data.
/// @param val The default value of the parameter.
#define BOTH_LABEL_DEAFULT_PARAM(type, name, label, val) \
    ADD_DEFAULT_PARAM(BasicRest::Direction::BOTH, type, name, label, val)

/// @def C2S_DEAFULT_PARAM(type, name, val)
/// @brief Add a parameter with a default value for the Client-to-Server (C2S) direction with the parameter label
/// being the same as the parameter name.
///
/// This macro is used to add a parameter to a REST request with
/// the same label as the parameter name and a default value. If the
/// parameter is not provided in the request, the default value will be used.
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param val The default value of the parameter.
#define C2S_DEAFULT_PARAM(type, name, val) C2S_LABEL_DEAFULT_PARAM(type, name, #name, val)

/// @def C2S_DEAFULT_PARAM(type, name, val)
/// @brief Add a parameter with a default value for the Server-to-Client (S2C) direction with the parameter
/// label being the same as the parameter name.
///
/// This macro is used to add a parameter to a REST request with
/// the same label as the parameter name and a default value. If the
/// parameter is not provided in the request, the default value will be used.
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param val The default value of the parameter.
#define S2C_DEAFULT_PARAM(type, name, val) S2C_LABEL_DEAFULT_PARAM(type, name, #name, val)

/// @def C2S_DEAFULT_PARAM(type, name, val)
/// @brief Add a parameter with a default value for the Client-to-Server (C2S) and Server-to-Client (S2C) directions
/// with the parameter label being the same as the parameter name.
///
/// This macro is used to add a parameter to a REST request with
/// the same label as the parameter name and a default value. If the
/// parameter is not provided in the request, the default value will be used.
/// @param type The data type of the parameter.
/// @param name The variable name of the parameter.
/// @param val The default value of the parameter.
#define BOTH_DEAFULT_PARAM(type, name, val) BOTH_LABEL_DEAFULT_PARAM(type, name, #name, val)

#endif // __REST_H__
