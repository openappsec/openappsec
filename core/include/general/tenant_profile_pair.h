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
    {
    }

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
    getPfofileId() const
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
