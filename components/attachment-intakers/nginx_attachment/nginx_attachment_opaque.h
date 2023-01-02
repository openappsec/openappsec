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

#ifndef __NGINX_ATTACHMENT_OPAQUE_H__
#define __NGINX_ATTACHMENT_OPAQUE_H__

#include <string>
#include <set>
#include <map>

#include "compression_utils.h"
#include "generic_rulebase/generic_rulebase_context.h"
#include "http_transaction_data.h"
#include "table_opaque.h"
#include "context.h"
#include "i_environment.h"
#include "buffer.h"

class NginxAttachmentOpaque : public TableOpaqueSerialize<NginxAttachmentOpaque>, Singleton::Consume<I_Environment>
{
public:
    NginxAttachmentOpaque(HttpTransactionData transaction_data);
    ~NginxAttachmentOpaque();

    void
    activateContext()
    {
        ctx.activate();
        gen_ctx.activate();
        if (session_tenant != "") {
            Singleton::Consume<I_Environment>::by<NginxAttachmentOpaque>()->setActiveTenantAndProfile(
                session_tenant,
                session_profile
            );
        }

    }

    void
    deactivateContext()
    {
        if (session_tenant != "") {
            Singleton::Consume<I_Environment>::by<NginxAttachmentOpaque>()->unsetActiveTenantAndProfile();
        }
        gen_ctx.deactivate();
        ctx.deactivate();
    }

    CompressionStream * getResponseCompressionStream() { return response_compression_stream; }
    HttpTransactionData & getTransactionData() { return transaction_data; }

// LCOV_EXCL_START - sync functions, can only be tested once the sync module exists
    template <typename T> void serialize(T &, uint) {}
    static std::unique_ptr<TableOpaqueBase> prototype();
// LCOV_EXCL_STOP

    static const std::string name() { return "NginxAttachmentOpaque"; }
    static uint currVer() { return 0; }
    static uint minVer() { return 0; }

    const std::string & getSessionTenant() const { return session_tenant; }
    void setSessionTenantAndProfile(const std::string &tenant, const std::string &profile);
    void setSourceIdentifier(const std::string &header_key, const std::string &source_identifier);
    const std::string & getSourceIdentifiersType() const;

    const std::string & getSessionUUID() const { return uuid; }

    void addToSavedData(const std::string &name, const std::string &data);
    void setSavedData(
        const std::string &name,
        const std::string &data,
        EnvKeyAttr::LogSection log_ctx = EnvKeyAttr::LogSection::NONE
    );

private:
    CompressionStream       *response_compression_stream;
    HttpTransactionData     transaction_data;
    GenericRulebaseContext  gen_ctx;
    Context                 ctx;
    std::string             session_tenant;
    std::string             session_profile;
    std::string             uuid;
    std::string             source_identifier;
    std::string             identifier_type;
    std::map<std::string, std::string> saved_data;
};

#endif // __NGINX_ATTACHMENT_OPAQUE_H__
