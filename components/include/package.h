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

#ifndef __PACKAGE_H__
#define __PACKAGE_H__

#include <string>
#include <map>

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#include "debug.h"
#include "maybe_res.h"

class Package
{
public:
    enum class ChecksumTypes { SHA1, SHA256, SHA512, MD5 };
    enum class PackageType { Service, SharedObject };

    const std::string & getDownloadPath() const { return download_path; }
    const std::string & getRelativeDownloadPath() const { return relative_path; }
    const std::string & getName() const { return name; }
    const std::string & getVersion() const { return version; }
    const std::string & getChecksum() const { return checksum_value; }
    const PackageType & getType() const { return package_type; }
    const std::vector<std::string> & getRequire() const { return require_packages; }
    const ChecksumTypes & getChecksumType() const { return checksum_type; }
    const Maybe<void> & isInstallable() const { return installable; }

    bool operator==(const Package &other) const;
    bool operator!=(const Package &other) const;

    void serialize(cereal::JSONOutputArchive & out_archive) const;
    void serialize(cereal::JSONInputArchive & in_archive);

private:
    template<typename T>
    std::string
    mapTypeToString(const T &type, const std::map<std::string, T> &type_mapper) const
    {
        for (auto &mapped_type : type_mapper) {
            if (mapped_type.second == type) return mapped_type.first;
        }

        dbgAssert(false) << "Unsupported type " << static_cast<int>(type);
        // Just satisfying the compiler, this return never reached
        return std::string();
    }

    Maybe<void> installable = Maybe<void>();
    std::string mirror;
    std::string name;
    std::string version;
    std::string download_path;
    std::string relative_path;
    ChecksumTypes checksum_type;
    std::string checksum_value;
    PackageType package_type;
    std::vector<std::string> require_packages;
};

#endif // __PACKAGE_H__
