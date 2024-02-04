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

#ifndef __I_OA_SCHEMA_UPDATER_H__
#define __I_OA_SCHEMA_UPDATER_H__

#include <string>
#include "i_transaction.h"
#include "../security_apps/waap/waap_clib/oasu_key_types.h"
#include "../security_apps/waap/waap_clib/events_for_oa_schema.h"

class I_OASUpdater
{
public:
    virtual void onKvt(const std::string &value, SchemaKeyType type, IWaf2Transaction &waf2Transaction) = 0;
    virtual void addOperationField(
        const std::string &operation_name,
        const std::string &operation_type,
        const std::string &field_name,
        IWaf2Transaction &waf2Transaction) = 0;
    virtual void removeGraphQLData(IWaf2Transaction &waf2Transaction) = 0;
    virtual void addActiveOperationName(
        const std::string &operation_name,
        IWaf2Transaction &waf2Transaction) = 0;
};

#endif // __I_OA_SCHEMA_UPDATER_H__
