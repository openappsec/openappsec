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

#ifndef __TENANT_PROFILE_PAIR_H__
#define __TENANT_PROFILE_PAIR_H__

#include <string>

#include "hash_combine.h"

class TenantProfilePair
{
public:
    TenantProfilePair(const std::string &_tenant_id, const std::string &_profile_id)
            :
        tenant_id(_tenant_id),
        profile_id(_profile_id)
    {}

    TenantProfilePair(const std::pair<std::string, std::string> &tenant_profile_pair)
            :
        tenant_id(tenant_profile_pair.first),
        profile_id(tenant_profile_pair.second)
    {}

    size_t
    hash() const
    {
        size_t seed = 0;
        hashCombine(seed, tenant_id);
        hashCombine(seed, profile_id);
        return seed;
    }

    bool
    operator==(const TenantProfilePair &other) const
    {
        return (tenant_id == other.tenant_id && profile_id == other.profile_id);
    }

    bool
    operator>(const TenantProfilePair &other) const
    {
        if (tenant_id > other.tenant_id) {
            return true;
        } else if (tenant_id == other.tenant_id && profile_id > other.profile_id) {
            return true;
        }
        return false;
    }

    bool
    operator<(const TenantProfilePair &other) const
    {
        return !(*this >= other);
    }

    bool
    operator>=(const TenantProfilePair &other) const
    {
        return (*this > other) || (*this == other);
    }

    bool
    operator<=(const TenantProfilePair &other) const
    {
        return !(*this > other);
    }

    std::string
    getTenantId() const
    {
        return tenant_id;
    }

    std::string
    getProfileId() const
    {
        return profile_id;
    }

private:
    std::string tenant_id;
    std::string profile_id;
};

namespace std
{

template <>
struct hash<TenantProfilePair>
{
    size_t operator()(const TenantProfilePair &tenant_profile) const { return tenant_profile.hash(); }
};

}

#endif // __TENANT_PROFILE_PAIR_H__
