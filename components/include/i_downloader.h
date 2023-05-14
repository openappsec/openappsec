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

#ifndef __I_DOWNLOADER_H__
#define __I_DOWNLOADER_H__

#include "i_orchestration_tools.h"
#include "i_update_communication.h"

#include <string>

class I_Downloader
{
public:
    virtual Maybe<std::string> downloadFileFromFog(
        const std::string &checksum,
        Package::ChecksumTypes,
        const GetResourceFile &resourse_file
    ) const = 0;

    virtual Maybe<std::map<std::pair<std::string, std::string>, std::string>>downloadVirtualFileFromFog(
        const GetResourceFile &resourse_file,
        Package::ChecksumTypes checksum_type
    ) const = 0;

    virtual Maybe<std::string> downloadFileFromURL(
        const std::string &url,
        const std::string &checksum,
        Package::ChecksumTypes checksum_type,
        const std::string &service_name
    ) const = 0;

    virtual std::string getProfileFromMap(const std::string &tenant_id) const = 0;
};

#endif // __I_DOWNLOADER_H__
