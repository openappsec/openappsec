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

#ifndef __IP_COMMON_C__
#define __IP_COMMON_C__

enum IpVersion {
    IP_VERSION_ANY = 0,
    IP_VERSION_4 = 4,
    IP_VERSION_6 = 6,
};

typedef enum IpVersion IpVersion;

typedef struct IpAddress {
    union {
        struct in_addr  ipv4;
        struct in6_addr ipv6;
    } ip;
#define addr4_t ip.ipv4
#define addr6_t ip.ipv6
    IpVersion ip_type;
} IpAddress;

typedef struct IPRange {
    IpAddress start;
    IpAddress end;
} IPRange;

typedef struct PortsRange {
    uint16_t start;
    uint16_t end;
} PortsRange;

typedef struct IpProtoRange {
    uint8_t start;
    uint8_t end;
} IpProtoRange;

typedef struct GDFilter {
    IPRange *source;
    unsigned int size;
} GDFilter;

#endif // __IP_COMMON_C__
