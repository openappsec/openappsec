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

#ifndef __INTELLIGENCE_QUERY_V2_H__
#define __INTELLIGENCE_QUERY_V2_H__

#include<vector>

#include "cereal/archives/json.hpp"
#include "intelligence_types_v2.h"
#include "query_request_v2.h"
#include "query_response_v2.h"
#include "bulk_query_response_v2.h"
#include "rest.h"

template <typename UserSerializableReplyAttr>
class IntelligenceQuery
{
public:
    IntelligenceQuery(QueryRequest &filter, bool is_pretty)
            :
        request(filter),
        response(),
        responses(),
        is_bulk(false),
        is_pretty(is_pretty)
    {}

    IntelligenceQuery(std::vector<QueryRequest> &filters, bool is_pretty)
            :
        requests(filters),
        response(),
        responses(),
        is_bulk(true),
        is_pretty(is_pretty)
    {}

    Maybe<std::string> genJson() const;
    bool loadJson(const std::string &json);

    void load(cereal::JSONInputArchive &ar);
    void save(cereal::JSONOutputArchive &ar) const;

    std::vector<AssetReply<UserSerializableReplyAttr>> getData();
    std::vector<Maybe<std::vector<AssetReply<UserSerializableReplyAttr>>>> getBulkData();
    ResponseStatus getResponseStatus();
    int getResponseAssetCollectionsSize() const { return response.getAssetCollectionsSize(); }
    const std::string & getResponseCursorVal() const { return response.getCursor(); }

    void activatePaging();
    Maybe<Intelligence_IS_V2::CursorState> getPagingStatus();
    void setRequestCursor(CursorState state, const std::string &value);

private:
    static QueryRequest dummy_query_request;
    static std::vector<QueryRequest> dummy_query_requests;
    std::vector<QueryRequest> &requests = dummy_query_requests;
    QueryRequest &request = dummy_query_request;
    IntelligenceQueryResponse<UserSerializableReplyAttr> response;
    std::vector<IntelligenceQueryResponse<UserSerializableReplyAttr>> responses;
    bool is_bulk;
    bool is_pretty;
};

#include "intelligence_query_v2_impl.h"

#endif // __INTELLIGENCE_QUERY_V2_H__
