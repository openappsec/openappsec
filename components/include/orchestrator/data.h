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

#ifndef __DATA_H__
#define __DATA_H__

#include <string>
#include <map>

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#include "debug.h"
#include "maybe_res.h"

class Data
{
public:
    enum class ChecksumTypes { SHA1, SHA256, SHA512, MD5 };

    const std::string & getDownloadPath() const { return download_path; }
    const std::string & getVersion() const { return version; }
    const std::string & getChecksum() const { return checksum_value; }
    const ChecksumTypes & getChecksumType() const { return checksum_type; }

    void serialize(cereal::JSONInputArchive & in_archive);

private:
    ChecksumTypes checksum_type = ChecksumTypes::SHA256;
    std::string version;
    std::string download_path;
    std::string checksum_value;
};

#endif // __DATA_H__
