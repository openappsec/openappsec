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

#include "orchestrator/data.h"

#include <map>

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

static const map<string, Data::ChecksumTypes> checksum_map = {
    { "sha1sum",   Data::ChecksumTypes::SHA1 },
    { "sha256sum", Data::ChecksumTypes::SHA256 },
    { "sha512sum", Data::ChecksumTypes::SHA512 },
    { "md5sum",    Data::ChecksumTypes::MD5 }
};

void
Data::serialize(JSONInputArchive &in_archive)
{
    string checksum_type_as_string;
    in_archive(make_nvp("checksumType", checksum_type_as_string));
    if (checksum_map.find(checksum_type_as_string) != checksum_map.end()) {
        checksum_type = checksum_map.at(checksum_type_as_string);
    } else {
        dbgWarning(D_ORCHESTRATOR) << "Unsupported checksum type: " << checksum_type_as_string;
        return;
    }
    in_archive(
        make_nvp("downloadPath", download_path),
        make_nvp("checksum", checksum_value),
        make_nvp("version", version)
    );
}
