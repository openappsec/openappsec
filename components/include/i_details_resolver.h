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

#ifndef __I_DETAILS_RESOLVER_H__
#define __I_DETAILS_RESOLVER_H__

#include "maybe_res.h"

#include <string>

class I_DetailsResolver
{
public:
    virtual Maybe<std::string> getHostname() = 0;
    virtual Maybe<std::string> getPlatform() = 0;
    virtual Maybe<std::string> getArch() = 0;
    virtual std::string getAgentVersion() = 0;
    virtual bool isKernelVersion3OrHigher() = 0;
    virtual bool isGwNotVsx() = 0;
    virtual bool isVersionEqualOrAboveR8110() = 0;
    virtual bool isReverseProxy() = 0;
    virtual Maybe<std::tuple<std::string, std::string, std::string>> parseNginxMetadata() = 0;
    virtual std::map<std::string, std::string> getResolvedDetails() = 0;
#if defined(gaia) || defined(smb)
    virtual bool compareCheckpointVersion(int cp_version, std::function<bool(int, int)> compare_operator) const = 0;
#endif // gaia || smb

protected:
    virtual ~I_DetailsResolver() {}
};

#endif // __I_DETAILS_RESOLVER_H__
