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

#ifndef __GET_RESOURCE_FILE_H__
#define __GET_RESOURCE_FILE_H__

#include <string>

#include "rest.h"
#include "i_messaging.h"

class GetResourceFile : public ClientRest
{
    class TenantResource : public ClientRest
    {
    public:
        TenantResource(
            const std::string &_tenant_id,
            const std::string &_profile_id,
            const std::string &_version,
            const std::string &_checksum)
                :
            tenant_id(_tenant_id),
            profile_id(_profile_id),
            version(_version),
            checksum(_checksum)
        {
        }

        TenantResource(const TenantResource &other)
        {
            tenant_id = other.tenant_id;
            profile_id = other.profile_id;
            version = other.version;
            checksum = other.checksum;
        }

        bool
        operator==(const TenantResource &other) const
        {
            return
                tenant_id.get() == other.tenant_id.get() &&
                profile_id.get() == other.profile_id.get() &&
                version.get()   == other.version.get() &&
                checksum.get()  == other.checksum.get();
        }

        C2S_LABEL_PARAM(std::string, tenant_id, "tenantId");
        C2S_LABEL_PARAM(std::string, profile_id, "profileId");
        C2S_LABEL_PARAM(std::string, version,   "version");
        C2S_LABEL_PARAM(std::string, checksum,  "checksum");
    };

public:
    enum class ResourceFileType {
        MANIFEST,
        POLICY,
        SETTINGS,
        DATA,
        VIRTUAL_SETTINGS,
        VIRTUAL_POLICY,

        COUNT
    };

    GetResourceFile() = default;

    GetResourceFile(const ResourceFileType _file_type)
            :
        file_type(_file_type)
    {
    }

    bool
    operator==(const GetResourceFile &other) const
    {
        if (file_type != other.file_type) return false;
        if (tenants.isActive() && other.tenants.isActive()) return tenants.get() == other.tenants.get();

        return (!tenants.isActive() && !other.tenants.isActive());
    }

    void
    addTenant(
        const std::string &tenant_id,
        const std::string &profile_id,
        const std::string &version,
        const std::string &checksum)
    {
        if (!isVirtual()) return;

        if (!tenants.isActive()) tenants = std::vector<TenantResource>();
        tenants.get().emplace_back(tenant_id, profile_id, version, checksum);
    }

    std::string
    getFileName() const
    {
        switch (file_type)
        {
            case ResourceFileType::MANIFEST:         return "manifest";
            case ResourceFileType::POLICY:           return "policy";
            case ResourceFileType::SETTINGS:         return "settings";
            case ResourceFileType::DATA:             return "data";
            case ResourceFileType::VIRTUAL_SETTINGS: return "virtualSettings";
            case ResourceFileType::VIRTUAL_POLICY:   return "virtualPolicy";
            default:
                dbgAssert(false) << "Unknown file type";
        }
        return std::string();
    }

    I_Messaging::Method
    getRequestMethod() const
    {
        return isVirtual() ? I_Messaging::Method::POST : I_Messaging::Method::GET;
    }

private:
    bool
    isVirtual() const
    {
        return
            file_type == ResourceFileType::VIRTUAL_SETTINGS ||
            file_type == ResourceFileType::VIRTUAL_POLICY;
    }

    C2S_LABEL_OPTIONAL_PARAM(std::vector<TenantResource>, tenants, "tenants");
    ResourceFileType file_type;
};

#endif // __GET_RESOURCE_FILE_H__
