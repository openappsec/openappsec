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

USE_DEBUG_FLAG(D_INTELLIGENCE);

using namespace Intelligence;
using namespace std;

Invalidation::Invalidation()
        :
    source_id(genError<string>("")),
    object_type(genError<string>("")),
    invalidation_type(genError<string>("")),
    listening_id(genError<string>("")),
    registration_id(genError<string>(""))
{}

Invalidation::Invalidation(const string &class_value)
        :
    source_id(genError<string>("")),
    object_type(genError<string>("")),
    invalidation_type(genError<string>("")),
    listening_id(genError<string>("")),
    registration_id(genError<string>(""))
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
Invalidation::startListening(
    I_Intelligence_IS_V2 *interface,
    const function<void(const Invalidation &)> &cb,
    const string &AgentId
)
{
    registration_id = to_string(boost::uuids::random_generator()());
    auto res = interface->registerInvalidation(*this, cb, AgentId);
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
    if (invalidation_type.ok()) {
        invalidation << ", \"invalidationType\": \"" << convertInvalidationType.at(*invalidation_type) << '"';
    }
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
Invalidation::attr_matches(const vector<IpAttributes> &current, const vector<IpAttributes> &other) const
{
    if (current.empty()) return true;
    for (const auto &attr : current) {
        for(const auto &other_attr : other) {
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

    if (invalidation_type.ok()) {
        if (!other.invalidation_type.ok() || *invalidation_type != *other.invalidation_type) return false;
    }

    if (source_id.ok()) {
        if (!other.source_id.ok() || *source_id != *other.source_id) return false;
    }

    if (!attr_matches(main_attributes, other.getMainAttributes())) return false;

    if(!attr_matches(attributes, other.getAttributes())) return false;

    return true;
}

void
Invalidation::serialize(cereal::JSONInputArchive &ar)
{
    std::string class_ = "";
    std::string category = "";
    std::string family = "";
    std::string group = "";
    std::string order = "";
    std::string kind = "";
    std::string object_type_;
    std::string invalidation_type_;
    std::string source_id_;
    uint listening_id_;
    std::string registration_id_;
    
    try {
        ar(cereal::make_nvp("class", class_));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("category", category));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("family", family));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("group", group));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("order", order));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("kind", kind));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("mainAttributes", main_attributes));
        ar(cereal::make_nvp("attributes", attributes));
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("objectType", object_type_));
        auto it = stringToObjectTypeMap.find(object_type_);
        if (it != stringToObjectTypeMap.end()) {
            object_type = it->second;
        } else {
            throw std::invalid_argument("Invalid string for ObjectType: " + object_type_);
        }
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("sourceId", source_id_));
        source_id = source_id_;
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("invalidationRegistrationId", registration_id_));
        registration_id = registration_id_;
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("invalidationType", invalidation_type_));
        auto it = stringToInvalidationTypeMap.find(invalidation_type_);
        if (it != stringToInvalidationTypeMap.end()) {
            invalidation_type = it->second;
        } else {
            throw std::invalid_argument("Invalid string for InvalidationType: " + invalidation_type_);
        }
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    try {
        ar(cereal::make_nvp("listeningId", listening_id_));
        listening_id = listening_id_;
    } catch (const cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }

    classifiers[ClassifierType::CLASS] = class_;
    classifiers[ClassifierType::CATEGORY] = category;
    classifiers[ClassifierType::FAMILY] = family;
    classifiers[ClassifierType::GROUP] = group;
    classifiers[ClassifierType::ORDER] = order;
    classifiers[ClassifierType::KIND] = kind;
}

Invalidation &
Invalidation::addAttr(const IpAttributes &attr)
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

Maybe<string>
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

IpAttributes &
IpAttributes::addIpv4Addresses(const string &val)
{
    ipv4_addresses.push_back(val);
    return *this;
}

IpAttributes &
IpAttributes::addIpv6Addresses(const string &val)
{
    ipv6_addresses.push_back(val);
    return *this;
}

IpAttributes &
IpAttributes::addIpv4AddressRanges(const IpAddressRange &val)
{
    ipv4_address_ranges.push_back(val);
    return *this;
}

IpAttributes &
IpAttributes::addIpv6AddressRanges(const IpAddressRange &val)
{
    ipv6_address_ranges.push_back(val);
    return *this;
}

Maybe<vector<string>, void>
IpAttributes::getIpv4Addresses() const
{
    if (ipv4_addresses.empty()) return genError<void>();
    return ipv4_addresses;
}

Maybe<vector<string>, void>
IpAttributes::getIpv6Addresses() const
{
    if (ipv6_addresses.empty()) return genError<void>();
    return ipv6_addresses;
}

Maybe<vector<IpAddressRange>, void>
IpAttributes::getIpv4AddressRanges() const
{
    if (ipv4_address_ranges.empty()) return genError<void>();
    return ipv4_address_ranges;
}

Maybe<vector<IpAddressRange>, void>
IpAttributes::getIpv6AddressRanges() const
{
    if (ipv6_address_ranges.empty()) return genError<void>();
    return ipv6_address_ranges;
}

Maybe<string, void>
IpAttributes::genObject() const
{
    stringstream attributes_ss;
    if (this->isEmpty()) return genError<void>();
    bool internal_first = true;
    bool first = true;
    attributes_ss << "{ ";
    if (!ipv4_addresses.empty()) {
        attributes_ss << "\"ipv4Addresses\": [ ";
        for (auto &attr : ipv4_addresses) {
            if (!internal_first) attributes_ss << ", ";
            attributes_ss << "\"" << attr << "\"";
            internal_first = false;
        }
        attributes_ss << " ]";
        first = false;
    }

    if (!ipv6_addresses.empty()) {
        if (!first) attributes_ss << ", ";
        attributes_ss << "\"ipv6Addresses\": [ ";
        internal_first = true;
        for (auto &attr : ipv6_addresses) {
            if (!internal_first) attributes_ss << ", ";
            attributes_ss << "\"" << attr << "\"";
            internal_first = false;
        }
        attributes_ss << " ]";
        first = false;
    }

    if (!ipv4_address_ranges.empty()) {
        if (!first) attributes_ss << ", ";
        attributes_ss << "\"ipv4AddressesRange\": [ ";
        internal_first = true;
        for (auto &attr : ipv4_address_ranges) {
            if (!internal_first) attributes_ss << ", ";
            attributes_ss << "{ \"max\": \"" << attr.getMax() << "\", \"min\": \"" << attr.getMin() << "\" }";
            internal_first = false;
        }
        attributes_ss << " ]";
        first = false;
    }

    if (!ipv6_address_ranges.empty()) {
        if (!first) attributes_ss << ", ";
        attributes_ss << "\"ipv6AddressesRange\": [ ";
        internal_first = true;
        for (auto &attr : ipv6_address_ranges) {
            if (!internal_first) attributes_ss << ", ";
            attributes_ss << "{ \"max\": \"" << attr.getMax() << "\", \"min\": \"" << attr.getMin() << "\" }";
            internal_first = false;
        }
        attributes_ss << " ]";
        first = false;
    }

    attributes_ss << " }";
    return attributes_ss.str();
}

bool
IpAttributes::isEmpty() const
{
    return
        ipv4_addresses.empty() &&
        ipv6_addresses.empty() &&
        ipv4_address_ranges.empty() &&
        ipv6_address_ranges.empty();
}

bool
IpAttributes::matches(const IpAttributes &other) const
{
    return
        ipv4_addresses == other.ipv4_addresses &&
        ipv6_addresses == other.ipv6_addresses &&
        ipv4_address_ranges == other.ipv4_address_ranges &&
        ipv6_address_ranges == other.ipv6_address_ranges;
}

void
IpAttributes::serialize(cereal::JSONInputArchive &ar)
{
    try {
        ar(cereal::make_nvp("ipv4Addresses", ipv4_addresses));
        ar(cereal::make_nvp("ipv4AddressesRange", ipv4_address_ranges));
        ar(cereal::make_nvp("ipv6Addresses", ipv6_addresses));
        ar(cereal::make_nvp("ipv6AddressesRange", ipv6_address_ranges));
    } catch (cereal::Exception &e) {
        dbgError(D_INTELLIGENCE) << e.what();
    }
}

void
IpAttributes::performOutputingSchema(ostream &out, int level)
{
    bool first = true;
    bool internal_first = true;
    RestHelper::printIndent(out, level) << "{\n";

    if (!ipv4_addresses.empty()) {
        RestHelper::printIndent(out, level + 1) << "\"ipv4Addresses\": [\n";
        for (auto &attr : ipv4_addresses) {
            if (!internal_first) out << ",\n";
            RestHelper::printIndent(out, level + 2) << "\"" << attr << "\"";
            internal_first = false;
        }
        out << "\n";
        RestHelper::printIndent(out, level + 1) << "]";
        first = false;
    }

    if (!ipv6_addresses.empty()) {
        if (!first) out << ",\n";
        RestHelper::printIndent(out, level + 1) << "\"ipv6Addresses\": [\n";
        internal_first = true;
        for (auto &attr : ipv6_addresses) {
            if (!internal_first) out << ",\n";
            RestHelper::printIndent(out, level + 2) << "\"" << attr << "\"";
            internal_first = false;
        }
        out << "\n";
        RestHelper::printIndent(out, level + 1) << "]";
        first = false;
    }

    if (!ipv4_address_ranges.empty()) {
        if (!first) out << ",\n";
        RestHelper::printIndent(out, level + 1) << "\"ipv4AddressesRange\": [\n";
        internal_first = true;
        for (auto &attr : ipv4_address_ranges) {
            if (!internal_first) out << ",\n";
            RestHelper::printIndent(out, level + 2) << "{\n";
            RestHelper::printIndent(out, level + 3) << "\"max\": \"" << attr.getMax() << "\",\n";
            RestHelper::printIndent(out, level + 3) << "\"min\": \"" << attr.getMin() << "\"\n";
            RestHelper::printIndent(out, level + 2) << "}";
            internal_first = false;
        }
        out << "\n";
        RestHelper::printIndent(out, level + 1) << "]";
        first = false;
    }

    if (!ipv6_address_ranges.empty()) {
        if (!first) out << ",\n";
        RestHelper::printIndent(out, level + 1) << "\"ipv6AddressesRange\": [\n";
        internal_first = true;
        for (auto &attr : ipv6_address_ranges) {
            if (!internal_first) out << ",\n";
            RestHelper::printIndent(out, level + 2) << "{\n";
            RestHelper::printIndent(out, level + 3) << "\"max\": \"" << attr.getMax() << "\",\n";
            RestHelper::printIndent(out, level + 3) << "\"min\": \"" << attr.getMin() << "\"\n";
            RestHelper::printIndent(out, level + 2) << "}";
            internal_first = false;
        }
        out << "\n";
        RestHelper::printIndent(out, level + 1) << "]";
        first = false;
    }

    RestHelper::printIndent(out, level) << "\n}";
}
