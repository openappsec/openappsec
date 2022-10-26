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

#pragma once
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

namespace Waap {
namespace Util {

struct CIDRData {
    std::string cidrString;
    struct in_addr ipCIDRV4;
    struct in6_addr ipCIDRV6;
    uint8_t networkBits;
    bool isIPV6;
    bool operator==(const CIDRData &other) const;
};

bool isCIDR(const std::string& strCIDR, CIDRData& cidr);
bool cidrMatch(const std::string& sourceip, const CIDRData& cidr);
bool cidrMatch(const std::string &sourceip, const std::string &target);

}
}
