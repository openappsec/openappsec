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

#include "cereal/archives/json.hpp"
#include "intelligence_types_v2.h"
#include "query_request_v2.h"
#include "query_response_v2.h"
#include "rest.h"

template <typename UserSerializableReplyAttr>
class IntelligenceQuery
{
public:
    IntelligenceQuery(QueryRequest &filter)
            :
        request(filter),
        response()
    {}

    Maybe<std::string> genJson() const;
    bool loadJson(const std::string &json);

    void load(cereal::JSONInputArchive &ar);
    void save(cereal::JSONOutputArchive &ar) const;

    std::vector<AssetReply<UserSerializableReplyAttr>> getData();
    ResponseStatus getResponseStatus() { return response.getResponseStatus(); }
    int getResponseAssetCollectionsSize() const { return response.getAssetCollectionsSize(); }
    const std::string & getResponseCursorVal() const { return response.getCursor(); }

    void activatePaging();
    Maybe<Intelligence_IS_V2::CursorState> getPagingStatus();
    void setRequestCursor(CursorState state, const std::string &value);

private:
    QueryRequest &request;
    IntelligenceQueryResponse<UserSerializableReplyAttr> response;
};

#include "intelligence_query_v2_impl.h"

#endif // __INTELLIGENCE_QUERY_V2_H__
