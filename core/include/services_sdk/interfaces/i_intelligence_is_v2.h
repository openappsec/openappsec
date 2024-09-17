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

#ifndef __I_INTELLIGENCE_IS_V2_H__
#define __I_INTELLIGENCE_IS_V2_H__

#include <chrono>
#include <string>

#include "intelligence_is_v2/asset_reply.h"
#include "intelligence_is_v2/intelligence_response.h"
#include "intelligence_is_v2/intelligence_types_v2.h"
#include "intelligence_is_v2/query_request_v2.h"
#include "messaging/messaging_enums.h"
#include "messaging/messaging_metadata.h"
#include "maybe_res.h"

namespace Intelligence {

class Invalidation;
class Response;

} // namespace Intelligence

class I_Intelligence_IS_V2
{
public:
    virtual bool sendInvalidation(const Intelligence::Invalidation &invalidation) const = 0;
    virtual bool isIntelligenceHealthy() const = 0;
    virtual Maybe<uint> registerInvalidation(
        const Intelligence::Invalidation &invalidation,
        const std::function<void(const Intelligence::Invalidation &)> &callback
    ) = 0;
    virtual void unregisterInvalidation(uint id) = 0;
    virtual Maybe<Intelligence::Response>
    getResponse(
        const std::vector<QueryRequest> &query_requests,
        bool is_pretty,
        bool is_bulk,
        bool is_proxy,
        const MessageMetadata &req_md
    ) const = 0;

    virtual Maybe<Intelligence::Response>
    getResponse(
        const QueryRequest &query_request,
        bool is_pretty,
        bool is_proxy,
        const MessageMetadata &req_md
    ) const = 0;

    template<typename Data>
    Maybe<std::vector<AssetReply<Data>>>
    queryIntelligence(
        QueryRequest &query_request,
        bool ignore_in_progress = false,
        bool is_pretty = true,
        bool is_proxy = false,
        MessageMetadata req_md = MessageMetadata("", 0)
    );

    template<typename Data>
    Maybe<std::vector<Maybe<std::vector<AssetReply<Data>>>>>
    queryIntelligence(
        std::vector<QueryRequest> &query_requests,
        bool is_pretty = true,
        bool is_proxy = false,
        MessageMetadata req_md = MessageMetadata("", 0)
    );

protected:
    virtual ~I_Intelligence_IS_V2() {}
};

#include "intelligence_is_v2/intelligence_interface_impl.h"

#endif // __I_INTELLIGENCE_IS_V2_H__
