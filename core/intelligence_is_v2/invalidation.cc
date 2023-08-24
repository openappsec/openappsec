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

#include "i_intelligence_is_v2.h"

using namespace Intelligence;
using namespace std;

Invalidation::Invalidation(const string &class_value)
        :
    source_id(genError<void>()),
    object_type(genError<void>()),
    listening_id(genError<void>())
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
Invalidation::setStringAttr(const string &attr, const string &val)
{
    string_main_attr[attr] = val;
    return *this;
}

Invalidation &
Invalidation::setStringSetAttr(const string &attr, const set<string> &val)
{
    set_string_main_attr[attr] = val;
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

Maybe<string, void>
Invalidation::getStringAttr(const string &attr) const
{
    auto val_ref = string_main_attr.find(attr);
    if (val_ref == string_main_attr.end()) return genError<void>();
    return val_ref->second;
}

Maybe<set<string>, void>
Invalidation::getStringSetAttr(const string &attr) const
{
    auto val_ref = set_string_main_attr.find(attr);
    if (val_ref == set_string_main_attr.end()) return genError<void>();
    return val_ref->second;
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
    if (source_id.ok()) invalidation <<", \"sourceId\": \"" << *source_id << '"';

    if (!string_main_attr.empty() || !set_string_main_attr.empty()) {
        invalidation << ", \"mainAttributes\": [ ";
        bool first = true;
        for (auto &attr : string_main_attr) {
            if (!first) invalidation << ", ";
            invalidation << "{ \"" << attr.first << "\": \"" << attr.second << "\" }";
            first = false;
        }

        for (auto &attr : set_string_main_attr) {
            if (!first) invalidation << ", ";
            auto val = makeSeparatedStr(attr.second, ", ");
            invalidation << "{ \"" << attr.first << "\": [ ";
            bool internal_first = true;
            for (auto &val : attr.second) {
                if (!internal_first) invalidation << ", ";
                invalidation << "\"" << val << "\"";
                internal_first = false;
            }
            invalidation << " ] }";
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
    if (!set_string_main_attr.empty() || !string_main_attr.empty()) {
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

    for (auto &key_value : string_main_attr) {
        if (!other.hasAttr(key_value.first, key_value.second)) return false;
    }


    for (auto &key_values : set_string_main_attr) {
        for (auto &value : key_values.second) {
            if (!other.hasAttr(key_values.first, value)) return false;
        }
    }

    return true;
}

bool
Invalidation::hasAttr(const string &key, const string &value) const
{
    auto string_elem = string_main_attr.find(key);
    if (string_elem != string_main_attr.end()) return string_elem->second == value;

    auto set_string_elem = set_string_main_attr.find(key);
    if (set_string_elem != set_string_main_attr.end()) {
        return set_string_elem->second.find(value) != set_string_elem->second.end();
    }

    return false;
}
