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

#include "intelligence_invalidation.h"

#include <sstream>
#include <boost/uuid/uuid_generators.hpp>
#include "boost/uuid/uuid_io.hpp"
#include "boost/uuid/uuid.hpp"

#include "i_intelligence_is_v2.h"

using namespace Intelligence;
using namespace std;

Invalidation::Invalidation(const string &class_value)
        :
    source_id(genError<void>()),
    object_type(genError<void>()),
    listening_id(genError<void>()),
    registration_id(genError<void>())
{
    setClassifier(ClassifierType::CLASS, class_value);
}

Invalidation &
Invalidation::setClassifier(ClassifierType type, const string &val)
{
    classifiers[type] = val;
    return *this;
}

Invalidation &
Invalidation::setSourceId(const string &id)
{
    source_id = id;
    return *this;
}

Invalidation &
Invalidation::setObjectType(ObjectType type)
{
    object_type = type;
    return *this;
}

Invalidation &
Invalidation::setInvalidationType(InvalidationType type)
{
    invalidation_type = type;
    return *this;
}

bool
Invalidation::report(I_Intelligence_IS_V2 *interface) const
{
    if (!isLegalInvalidation()) return false;
    return interface->sendInvalidation(*this);
}

Maybe<uint>
Invalidation::startListening(I_Intelligence_IS_V2 *interface, const function<void(const Invalidation &)> &cb)
{
    registration_id = to_string(boost::uuids::random_generator()());
    auto res = interface->registerInvalidation(*this, cb);
    if (res.ok()) listening_id = *res;
    return res;
}

void
Invalidation::stopListening(I_Intelligence_IS_V2 *interface)
{
    if (listening_id.ok()) interface->unregisterInvalidation(*listening_id);
}

static const map<Intelligence::ObjectType, string> convertObjectType = {
    { Intelligence::ObjectType::ASSET, "asset" },
    { Intelligence::ObjectType::ZONE, "zone" },
    { Intelligence::ObjectType::POLICY_PACKAGE, "policyPackage" },
    { Intelligence::ObjectType::CONFIGURATION, "configuration" },
    { Intelligence::ObjectType::SESSION, "session" },
    { Intelligence::ObjectType::SHORTLIVED, "shortLived" }
};

static const map<Intelligence::InvalidationType, string> convertInvalidationType = {
    { Intelligence::InvalidationType::ADD, "add" },
    { Intelligence::InvalidationType::DELETE, "delete" },
    { Intelligence::InvalidationType::UPDATE, "update" }
};

Maybe<string>
Invalidation::genJson() const
{
    if (!isLegalInvalidation()) return genError("Incomplete intelligence invalidation");

    stringstream invalidation;

    invalidation << "{ \"invalidations\": [ " << genObject() <<" ] }";

    return invalidation.str();
}

string
Invalidation::genObject() const
{
    stringstream invalidation;

    invalidation << "{ \"class\": \"" << classifiers[ClassifierType::CLASS] << '"';
    if (classifiers[ClassifierType::CATEGORY] != "") {
        invalidation <<", \"category\": \"" << classifiers[ClassifierType::CATEGORY] << '"';
    }
    if (classifiers[ClassifierType::FAMILY] != "") {
        invalidation <<", \"family\": \"" << classifiers[ClassifierType::FAMILY] << '"';
    }
    if (classifiers[ClassifierType::GROUP] != "") {
        invalidation <<", \"group\": \"" << classifiers[ClassifierType::GROUP] << '"';
    }
    if (classifiers[ClassifierType::ORDER] != "") {
        invalidation <<", \"order\": \"" << classifiers[ClassifierType::ORDER] << '"';
    }
    if (classifiers[ClassifierType::KIND] != "") {
        invalidation <<", \"kind\": \"" << classifiers[ClassifierType::KIND] << '"';
    }

    if (object_type.ok()) invalidation <<", \"objectType\": \"" << convertObjectType.at(*object_type) << '"';
    invalidation << ", \"invalidationType\": \"" << convertInvalidationType.at(invalidation_type) << '"';
    if (source_id.ok()) invalidation <<", \"sourceId\": \"" << *source_id << '"';
    if (registration_id.ok()) invalidation <<", \"invalidationRegistrationId\": \"" << *registration_id << '"';

    if (!main_attributes.empty()) {
        invalidation << ", \"mainAttributes\": [ ";
        bool first = true;
        for (auto &main_attr : main_attributes) {
            if (!first) invalidation << ", ";
            auto val = main_attr.genObject();
            if (!val.ok()) continue;
            invalidation << *val;
            first = false;
        }
        invalidation << " ]";
    }

    if (!attributes.empty()) {
        invalidation << ", \"attributes\": [ ";
        bool first = true;
        for (auto &attr : attributes) {
            if (!first) invalidation << ", ";
            auto val = attr.genObject();
            if (!val.ok()) continue;
            invalidation << *val;
            first = false;
        }

        invalidation << " ]";
    }

    invalidation << " }";

    return invalidation.str();
}

bool
Invalidation::isLegalInvalidation() const
{
    if (!main_attributes.empty() || !attributes.empty()) {
        if (classifiers[ClassifierType::FAMILY] == "") return false;
    }

    bool is_prev_empty = false;
    for (auto &classifer : classifiers) {
        if (is_prev_empty && classifer != "") return false;
        is_prev_empty = classifer == "";
    }

    return true;
}

template <>
class EnumCount<ClassifierType> : public EnumCountSpecialization<ClassifierType, 6> {};

bool
Invalidation::attr_matches(const vector<StrAttributes> &current, const vector<StrAttributes> &other) const
{
    if (current.empty()) return true;
    for (auto &attr : current) {
        for(auto &other_attr : other) {
            if (attr.matches(other_attr)) return true;
        }
    }
    return false;
}

bool
Invalidation::matches(const Invalidation &other) const
{
    for (auto key : NGEN::Range<ClassifierType>()) {
        if (classifiers[key] != "" && classifiers[key] != other.classifiers[key]) return false;
    }

    if (object_type.ok()) {
        if (!other.object_type.ok() || *object_type != *other.object_type) return false;
    }

    if (source_id.ok()) {
        if (!other.source_id.ok() || *source_id != *other.source_id) return false;
    }

    if (!attr_matches(main_attributes, other.getMainAttributes())) return false;

    if(!attr_matches(attributes, other.getAttributes())) return false;

    return true;
}

Invalidation &
Invalidation::addAttr(const StrAttributes &attr)
{
    attributes.emplace_back(attr);
    return *this;
}

Invalidation &
Invalidation::addMainAttr(const StrAttributes &attr)
{
    main_attributes.emplace_back(attr);
    return *this;
}

Maybe<string, void>
Invalidation::getRegistrationID() const{
    return registration_id;
}

StrAttributes &
StrAttributes::addStringAttr(const std::string &attr, const std::string &val)
{
    string_attr[attr] = val;
    return *this;
}

StrAttributes &
StrAttributes::addStringSetAttr(const std::string &attr, const std::set<std::string> &val)
{
    set_string_attr[attr] = val;
    return *this;
}

Maybe<std::string, void>
StrAttributes::getStringAttr(const std::string &attr) const
{
    auto val_ref = string_attr.find(attr);
    if (val_ref == string_attr.end()) return genError<void>();
    return val_ref->second;
}

Maybe<std::set<std::string>, void>
StrAttributes::getStringSetAttr(const string &attr) const
{
    auto val_ref = set_string_attr.find(attr);
    if (val_ref == set_string_attr.end()) return genError<void>();
    return val_ref->second;
}

Maybe<std::string, void>
StrAttributes::genObject() const
{
    stringstream attributes_ss;
    if (string_attr.empty() && set_string_attr.empty()) return genError<void>();
    bool first = true;
    attributes_ss << "{ ";
    for (auto &attr : string_attr) {
        if (!first) attributes_ss << ", ";
        attributes_ss << "\"" << attr.first << "\": \"" << attr.second << "\"";
        first = false;
    }

    for (auto &attr : set_string_attr) {
        if (!first) attributes_ss << ", ";
        auto val = makeSeparatedStr(attr.second, ", ");
        attributes_ss << "\"" << attr.first << "\": [ ";
        bool internal_first = true;
        for (auto &value : attr.second) {
            if (!internal_first) attributes_ss << ", ";
            attributes_ss << "\"" << value << "\"";
            internal_first = false;
        }
        attributes_ss << " ]";
        first = false;
    }
    attributes_ss << " }";
    return attributes_ss.str();
}

bool
StrAttributes::isEmpty() const
{
    return string_attr.empty() && set_string_attr.empty();
}

bool
StrAttributes::hasAttr(const string &key, const string &value) const
{
    auto string_elem = string_attr.find(key);
    if (string_elem != string_attr.end()) return string_elem->second == value;

    auto set_string_elem = set_string_attr.find(key);
    if (set_string_elem != set_string_attr.end()) {
        return set_string_elem->second.find(value) != set_string_elem->second.end();
    }

    return false;
}

bool
StrAttributes::matches(const StrAttributes &other) const
{
    for (auto &key_value : string_attr) {
        if (!other.hasAttr(key_value.first, key_value.second)) return false;
    }

    for (auto &key_values : set_string_attr) {
        for (auto &value : key_values.second) {
            if (!other.hasAttr(key_values.first, value)) return false;
        }
    }

    return true;
}

void
StrAttributes::serialize(cereal::JSONInputArchive &ar)
{
    SerializableMultiMap<string, set<string>> attributes_map;
    attributes_map.load(ar);
    string_attr = attributes_map.getMap<string>();
    set_string_attr = attributes_map.getMap<set<string>>();
}

void
StrAttributes::performOutputingSchema(ostream &out, int level) {
    bool first = true;
    RestHelper::printIndent(out, level) << "{\n";
    for (auto &attr : string_attr) {
        if (!first) out << ",\n";
        RestHelper::printIndent(out, level + 1) << "\"" << attr.first << "\": \"" << attr.second << "\"";
        first = false;
    }

    for (auto &attr : set_string_attr) {
        if (!first) out << ",\n";
        RestHelper::printIndent(out, level + 1) << "\"" << attr.first << "\": [\n";
        bool internal_first = true;
        for (auto &value : attr.second) {
            if (!internal_first) out << ",\n";
            RestHelper::printIndent(out, level + 2) << "\"" << value << "\"";
            internal_first = false;
        }
        out << "\n";
        RestHelper::printIndent(out, level + 1) << "]\n";
        first = false;
    }
    RestHelper::printIndent(out, level) << "}";
}
