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

#ifndef __IP_UTILITIES_H__
#define __IP_UTILITIES_H__

#include <map>
#include <sys/types.h>
#include <ifaddrs.h>
#include <string.h>
#include <vector>
#include <arpa/inet.h>

#include "c_common/ip_common.h"
#include "common.h"
#include "maybe_res.h"
#include "debug.h"

// LCOV_EXCL_START Reason: temporary until we add relevant UT until 07/10
bool operator<(const IpAddress &this_ip_addr, const IpAddress &other_ip_addr);

bool operator==(const IpAddress &this_ip_addr, const IpAddress &other_ip_addr);
// LCOV_EXCL_STOP

Maybe<std::pair<std::string, int>> extractAddressAndMaskSize(const std::string &cidr);

template<typename Integer>
std::pair<Integer, Integer> applyMaskOnAddress(const std::vector<Integer> &oct, Integer mask);

Maybe<std::pair<std::string, std::string>> createRangeFromCidrV4(const std::pair<std::string, int> &cidr_values);

Maybe<std::pair<std::string, std::string>> createRangeFromCidrV6(const std::pair<std::string, int> &cidr_values);

namespace IPUtilities {
Maybe<std::map<IpAddress, std::string>> getInterfaceIPs();

Maybe<std::pair<std::string, std::string>> createRangeFromCidr(const std::string &cidr);

bool isIpAddrInRange(const IPRange &rule_ip_range, const IpAddress &ip_addr);

std::string IpAddrToString(const IpAddress &address);

IpAddress createIpFromString(const std::string &ip_string);

template <typename Range, typename Type>
Maybe<Range> createRangeFromString(const std::string &range, const std::string &type_name);

using IpProto = uint8_t;
using Port = uint16_t;

class IpAttrFromString
{
public:
    IpAttrFromString(const std::string &in_data) : data(in_data) {}

    operator Maybe<IpAddress>();
    operator Maybe<IpProto>();
    operator Maybe<Port>();

private:
    std::string data;
};

template <typename Range, typename Type>
Maybe<Range>
createRangeFromString(const std::string &range, const std::string &type_name)
{
    std::string range_start;
    std::string range_end;
    size_t delimiter_pos = range.find("/");
    if (delimiter_pos != std::string::npos) {
        auto cidr = IPUtilities::createRangeFromCidr(range);
        if (!cidr.ok()) return genError("Couldn't create ip range from CIDR, error: " + cidr.getErr());
        range_start = cidr.unpack().first;
        range_end = cidr.unpack().second;
    } else {
        delimiter_pos = range.find("-");
        range_start = range.substr(0, delimiter_pos);
        range_end = delimiter_pos == std::string::npos ? range_start : range.substr(delimiter_pos + 1);
    }

    Maybe<Type> range_start_value = IpAttrFromString(range_start);
    if (!range_start_value.ok()) {
        return genError("provided value is not a legal " + type_name + ". Provided value: " + range_start);
    }

    Maybe<Type> range_end_value = IpAttrFromString(range_end);
    if (!range_end_value.ok()) {
        return genError("provided value is not a legal " + type_name + ". Provided value: " + range_end);
    }

    if (*range_end_value < *range_start_value) {
        return genError("Could not create " + type_name + "range. Error: start value is greater than end value");
    }
    return Range{.start = *range_start_value, .end = *range_end_value};
}
}
#endif // __IP_UTILITIES_H__
