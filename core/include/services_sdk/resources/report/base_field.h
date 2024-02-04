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

#ifndef __BASE_FIELD_H__
#define __BASE_FIELD_H__

#include "cereal/types/string.hpp"
#include "cereal/types/set.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/archives/json.hpp"
#include <memory>
#include <vector>
#include <sstream>
#include "common.h"
#include "debug.h"
#include "flags.h"
#include "config.h"

enum class LogFieldOption { XORANDB64, COUNT };

class LogField : Singleton::Consume<I_Environment>
{
    class Details
    {
    public:
        template <typename T>
        static T obfuscateChkPoint(const T &t) { return t; }

        static std::string obfuscateChkPoint(const std::string &orig);

        template <typename T>
        static std::string
        getValueAsString(const T &val)
        {
            std::stringstream stream;
            stream << val;
            return stream.str();
        }

        template <typename T>
        static std::string
        getValueAsString(const std::vector<T> &val)
        {
            std::vector<std::string> tmp;
            tmp.reserve(val.size());
            for (auto &elem : val) {
                tmp.push_back(getValueAsString(elem));
            }
            return "[ " + makeSeparatedStr(tmp, ", ") + " ]";
        }

    private:
        static const std::string cp_xor;
        static const std::string cp_xor_label;
    };

    class BaseField
    {
    public:
        BaseField(const std::string &_name) : name(_name) {}
        virtual ~BaseField() {}

        virtual void serialize(cereal::JSONOutputArchive &ar) const = 0;
        virtual void addFields(const LogField &log) = 0;
        virtual std::string getSyslogAndCef() const = 0;

        template <typename ... Strings>
        Maybe<std::string, void>
        getString(const std::string &path, const Strings & ... rest_of_path) const
        {
            auto sub_ptr = getSubField(path);
            if (!sub_ptr.ok()) return genError("");
            return (*sub_ptr).getString(rest_of_path ...);
        }

        virtual Maybe<std::string, void> getString() const = 0;
        virtual const Maybe<LogField, void> getSubField(const std::string &sub) const = 0;

        std::string name;
    };

    template <class T>
    class TypedField : public BaseField
    {
    public:
        template <typename ... Flags>
        TypedField(const std::string &name, const T &_value, Flags ... flags) : BaseField(name), value(_value)
        {
            setFlags(flags ...);
        }

        void
        serialize(cereal::JSONOutputArchive &ar) const override
        {
            ar(cereal::make_nvp(name, getValue()));
        }

        std::string
        getSyslogAndCef() const override
        {
            std::string value(Details::getValueAsString(getValue()));

            std::string encoded_value;
            encoded_value.reserve(value.size() + 6);
            for (char ch : value) {
                switch (ch) {
                    case '\\': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('\\');
                        break;
                    }
                    case '\n': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('n');
                        break;
                    }
                    case '\r': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('r');
                        break;
                    }
                    case '"': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('"');
                        break;
                    }
                    case '\'': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('\'');
                        break;
                    }
                    case ']': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back(']');
                        break;
                    }
                    case '=': {
                        encoded_value.push_back('\\');
                        encoded_value.push_back('=');
                        break;
                    }
                    default: {
                        encoded_value.push_back(ch);
                    }
                }
            }

            return name + "=\"" + encoded_value + "\"";
        }

        // LCOV_EXCL_START Reason: seems that assert prevent the LCOV from identifying that method was tested
        void
        addFields(const LogField &)
        {
            dbgAssert(false) << "Trying to add a log field to a 'type'ed field";
        }
        // LCOV_EXCL_STOP

        Maybe<std::string, void> getString() const override { return Details::getValueAsString(getValue()); }
        const Maybe<LogField, void> getSubField(const std::string &) const override { return genError(""); }

    private:
        template <typename ... Flags>
        void
        setFlags(LogFieldOption option, Flags ... flags)
        {
            setFlags(option);
            setFlags(flags...);
        }

        void
        setFlags(LogFieldOption option)
        {
            options.setFlag(option);
        }

        void setFlags() {}

        T
        getValue() const
        {
            if (!options.isSet(LogFieldOption::XORANDB64)) return value;
            auto env = Singleton::Consume<I_Environment>::by<LogField>();
            auto should_obfuscate = env->get<bool>("Obfuscate log field");
            if (!should_obfuscate.ok() || !(*should_obfuscate)) return value;
            if (!getProfileAgentSettingWithDefault<bool>(true, "agent.config.log.obfuscation")) return value;

            return Details::obfuscateChkPoint(value);
        }

        T value;
        Flags<LogFieldOption> options;
    };

    class AggField : public BaseField
    {
    public:
        AggField(std::string name) : BaseField(name) {}

        void
        serialize(cereal::JSONOutputArchive &ar) const override
        {
            // Our JSON format calls for things to be kept as an object, not an array, so we have a little work to do
            ar.setNextName(name.c_str());
            ar.startNode();
            for (auto &field : fields) {
                field.serialize(ar);
            }
            ar.finishNode();
        }

        std::string
        getSyslogAndCef() const override
        {
            if (fields.size() == 0) return "";

            std::string res;
            for (auto &field : fields) {
                if (res.size() > 0) res += " ";
                res += field.getSyslogAndCef();
            }
            return res;
        }

        void
        addFields(const LogField &f) override
        {
            fields.emplace_back(f);
        }

        Maybe<std::string, void> getString() const override { return genError(""); }

        const Maybe<LogField, void>
        getSubField(const std::string &sub) const override
        {
            for (auto &field : fields) {
                if (field.field->name == sub) return field;
            }
            return genError("");
        }

    private:
        std::vector<LogField> fields;
    };

public:
    template <typename T, typename ... Flags>
    LogField(const std::string &name, const T &value, Flags ... flags)
            :
        field(std::make_shared<TypedField<T>>(name, value, flags...))
    {
    }

    template <typename ... Flags>
    LogField(const std::string &name, const char *value, Flags ...flags)
            :
        LogField(name, std::string(value), flags...)
    {
    }

    LogField(const std::string &name) : field(std::make_shared<AggField>(name)) {}
    LogField(const std::string &name, const LogField &f) : LogField(name) { addFields(f); }

    template <typename Archive>
    void
    serialize(Archive &ar) const
    {
        field->serialize(ar);
    }

    std::string
    getSyslogAndCef() const
    {
        return field->getSyslogAndCef();
    }

    void
    addFields(const LogField &f)
    {
        field->addFields(f);
    }

    template <typename ... Strings>
    Maybe<std::string, void> getString(const Strings & ... path) const { return field->getString(path ...); }

private:
    std::shared_ptr<BaseField> field;
};

#endif // __BASE_FIELD_H__
