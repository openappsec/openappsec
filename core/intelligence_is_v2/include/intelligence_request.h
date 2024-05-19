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

#ifndef __INTELLIGENCE_REQUEST_H__
#define __INTELLIGENCE_REQUEST_H__
#include "intelligence_is_v2/query_request_v2.h"
#include "messaging/messaging_enums.h"
#include "messaging/messaging_metadata.h"

#include <vector>
#include "maybe_res.h"

namespace Intelligence {

class IntelligenceRequest : ClientRest
{
public:
    IntelligenceRequest(
        const std::vector<QueryRequest> &queries,
        bool is_pretty,
        bool is_bulk,
        const MessageMetadata &req_md
    )
            :
        queries(queries), is_pretty(is_pretty), is_bulk(is_bulk), req_md(req_md)
    {}

    Maybe<void> checkAssetsLimit() const;
    Maybe<void> checkMinConfidence() const;
    bool isPagingAllowed() const;
    bool isPagingActivated() const;
    Maybe<bool> isPagingFinished() const;
    Maybe<Intelligence_IS_V2::CursorState> getPagingStatus() const;
    Maybe<std::string> genJson() const;

    size_t getSize() const { return queries.size(); }
    bool isBulk() const { return is_bulk; }
    const MessageMetadata & getReqMD() const { return req_md; }

private:
    const std::vector<QueryRequest> &queries;
    bool is_pretty = true;
    bool is_bulk = false;
    Maybe<std::string> response_from_fog = genError("Uninitialized");
    const MessageMetadata &req_md;
};

}

#endif // __INTELLIGENCE_REQUEST_H__
