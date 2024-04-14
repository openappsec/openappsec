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

#ifndef __INTELLIGENCE_INVALIDATION_H__
#define __INTELLIGENCE_INVALIDATION_H__

#include <functional>
#include <map>
#include <string>
#include <set>
#include <cereal/archives/json.hpp>

#include "maybe_res.h"
#include "enum_array.h"

class I_Intelligence_IS_V2;

namespace Intelligence
{

enum class ClassifierType { CLASS, CATEGORY, FAMILY, GROUP, ORDER, KIND };
enum class ObjectType { ASSET, ZONE, POLICY_PACKAGE, CONFIGURATION, SESSION, SHORTLIVED };
enum class InvalidationType { ADD, DELETE, UPDATE };

class StrAttributes
{
public:
    StrAttributes() = default;
    StrAttributes & addStringAttr(const std::string &attr, const std::string &val);
    StrAttributes & addStringSetAttr(const std::string &attr, const std::set<std::string> &val);
    Maybe<std::string, void> getStringAttr(const std::string &attr) const;
    Maybe<std::set<std::string>, void> getStringSetAttr(const std::string &attr) const;
    Maybe<std::string, void> genObject() const;
    bool isEmpty() const;
    bool matches(const StrAttributes &other) const;
    void serialize(cereal::JSONInputArchive &ar);
    void performOutputingSchema(std::ostream &, int);

private:
    bool hasAttr(const std::string &key, const std::string &value) const;

    std::map<std::string, std::string> string_attr;
    std::map<std::string, std::set<std::string>> set_string_attr;
};

class Invalidation
{
public:
    Invalidation(const std::string &class_value);

    Invalidation & setClassifier(ClassifierType type, const std::string &val);
    Invalidation & addMainAttr(const StrAttributes &attr);
    Invalidation & addAttr(const StrAttributes &attr);
    Invalidation & setSourceId(const std::string &id);
    Invalidation & setObjectType(ObjectType type);
    Invalidation & setInvalidationType(InvalidationType type);

    std::string getClassifier(ClassifierType type) const { return classifiers[type]; }
    std::vector<StrAttributes> getMainAttributes() const { return main_attributes; }
    std::vector<StrAttributes> getAttributes() const { return attributes; }
    const Maybe<std::string, void> & getSourceId() const { return source_id; }
    const Maybe<ObjectType, void> & getObjectType() const { return object_type; }
    InvalidationType getInvalidationType() const { return invalidation_type; }
    Maybe<std::string, void> getRegistrationID() const;

    bool report(I_Intelligence_IS_V2 *interface) const;

    Maybe<uint> startListening(I_Intelligence_IS_V2 *interface, const std::function<void(const Invalidation &)> &cb);
    void stopListening(I_Intelligence_IS_V2 *interface);

    Maybe<std::string> genJson() const;
    std::string genObject() const;
    bool isLegalInvalidation() const;

    bool matches(const Invalidation &other) const;

private:
    bool attr_matches(const std::vector<StrAttributes> &current, const std::vector<StrAttributes> &other) const;

    EnumArray<ClassifierType, std::string, 6> classifiers;
    std::vector<StrAttributes> main_attributes;
    std::vector<StrAttributes> attributes;
    Maybe<std::string, void> source_id;
    Maybe<ObjectType, void> object_type;
    InvalidationType invalidation_type = InvalidationType::ADD;
    Maybe<uint, void> listening_id;
    Maybe<std::string, void> registration_id;
};

} // namespace Intelligence

#endif // __INTELLIGENCE_INVALIDATION_H__
