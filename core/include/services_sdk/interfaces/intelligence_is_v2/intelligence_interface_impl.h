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

#ifndef __INTELLIGENCE_INTERFACE_IMPL_H__
#define __INTELLIGENCE_INTERFACE_IMPL_H__

#ifndef __I_INTELLIGENCE_IS_V2_H__
#error intelligence_interface_impl.h should not be included directly!
#endif // __I_INTELLIGENCE_IS_V2_H__

template <typename Data>
Maybe<std::vector<AssetReply<Data>>>
I_Intelligence_IS_V2::queryIntelligence(
    QueryRequest &query_request,
    bool ignore_in_progress,
    bool is_pretty,
    MessageMetadata req_md
)
{
    auto response = getResponse(query_request, is_pretty, req_md);

    if (!response.ok()) return response.passErr();
    auto serializable_response = response->getSerializableResponse<Data>();
    if (!query_request.isPagingActivated()) return serializable_response.getData();
    if (serializable_response.isLast(query_request.getAssetsLimit())) {
        query_request.setCursor(Intelligence_IS_V2::CursorState::DONE, "");
    } else {
        query_request.setCursor(Intelligence_IS_V2::CursorState::IN_PROGRESS, response->getCursor());
        if (ignore_in_progress && response->getResponseStatus() == Intelligence_IS_V2::ResponseStatus::IN_PROGRESS) {
            return genError("Query intelligence response with InProgress status");
        }
    }

    return serializable_response.getData();
}

template<typename Data>
Maybe<std::vector<Maybe<std::vector<AssetReply<Data>>>>>
I_Intelligence_IS_V2::queryIntelligence(
    std::vector<QueryRequest> &query_requests,
    bool is_pretty,
    MessageMetadata req_md
)
{
    auto res = getResponse(query_requests, is_pretty, true, req_md);
    if (!res.ok()) return res.passErr();

    return res->getBulkData<Data>();
}

#endif // __INTELLIGENCE_INTERFACE_IMPL_H__
