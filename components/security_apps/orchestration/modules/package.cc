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

#include "package.h"

#include <map>

using namespace std;
using namespace cereal;

const map<string, Package::ChecksumTypes> checksumMap = {
    { "sha1sum",        Package::ChecksumTypes::SHA1 },
    { "sha256sum",      Package::ChecksumTypes::SHA256 },
    { "sha512sum",      Package::ChecksumTypes::SHA512 },
    { "md5sum",         Package::ChecksumTypes::MD5 },
};

const map<string, Package::PackageType> packageTypeMap = {
    { "service",        Package::PackageType::Service },
    { "shared objects", Package::PackageType::SharedObject },
};

bool
Package::operator==(const Package &other) const
{
    return checksum_type == other.getChecksumType() && checksum_value == other.getChecksum();
}

bool
Package::operator!=(const Package &other) const
{
    return !((*this) == other);
}

void
Package::serialize(JSONOutputArchive & out_archive) const
{
    string type = mapTypeToString<PackageType>(package_type, packageTypeMap);
    string checksum_type_as_string = mapTypeToString<ChecksumTypes>(checksum_type, checksumMap);
    out_archive(make_nvp("download-path",   download_path));
    out_archive(make_nvp("relative-path",    relative_path));
    out_archive(make_nvp("version",         version));
    out_archive(make_nvp("name",            name));
    out_archive(make_nvp("checksum-type",   checksum_type_as_string));
    out_archive(make_nvp("checksum",        checksum_value));
    out_archive(make_nvp("package-type",    type));

    if (require_packages.size() > 0) {
        out_archive(make_nvp("require", require_packages));
    }

    if (!installable.ok()) {
        out_archive(make_nvp("status", installable.ok()));
        out_archive(make_nvp("message", installable.getErr()));
    }
}

void
Package::serialize(JSONInputArchive & in_archive)
{
    string type;
    string checksum_type_as_string;
    in_archive(make_nvp("download-path",   download_path));
    in_archive(make_nvp("version",         version));
    in_archive(make_nvp("name",            name));
    in_archive(make_nvp("checksum-type",   checksum_type_as_string));
    in_archive(make_nvp("checksum",        checksum_value));
    in_archive(make_nvp("package-type",    type));

    try {
        in_archive(make_nvp("relative-path",    relative_path));
    } catch (...) {
        in_archive.setNextName(nullptr);
    }

    try {
        in_archive(make_nvp("require", require_packages));
    } catch (...) {
        in_archive.setNextName(nullptr);
    }

    bool is_installable = true;
    try {
        in_archive(make_nvp("status", is_installable));
    } catch (...) {
        in_archive.setNextName(nullptr);
    }

    if (!is_installable) {
        string error_message;
        try {
            in_archive(make_nvp("message", error_message));
        } catch (...) {
            in_archive.setNextName(nullptr);
        }
        installable = genError(error_message);
    }

    for (auto &character : name) {
        // Name Validation: should include only: decimal digit / letter / '.' / '_' / '-'
        if (!isalnum(character) && character != '.' && character != '_' && character != '-') {
            throw Exception(name + " is invalid package name");
        }
    }

    auto checksum_type_value = checksumMap.find(checksum_type_as_string);
    if (checksum_type_value == checksumMap.end()) {
        throw Exception(checksum_type_as_string + " isn't a valid checksum type at " + name);
    }
    checksum_type = checksum_type_value->second;

    auto package_type_value = packageTypeMap.find(type);
    if (package_type_value == packageTypeMap.end()) {
        throw Exception(checksum_type_as_string + " isn't a valid package type at " + name);
    }
    package_type = package_type_value->second;
}
