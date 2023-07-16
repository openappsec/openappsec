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

#ifndef __INTELLIGENCE_QUERY_V2_IMPL_H_
#define __INTELLIGENCE_QUERY_V2_IMPL_H_

#ifndef __INTELLIGENCE_QUERY_V2_H__
#error intelligence_query_impl_v2.h should not be included directly!
#endif // __INTELLIGENCE_QUERY_V2_H__

#include <sstream>
#include "json_stream.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReplyAttr>
QueryRequest IntelligenceQuery<UserSerializableReplyAttr>::dummy_query_request = QueryRequest();

template <typename UserSerializableReplyAttr>
std::vector<QueryRequest> IntelligenceQuery<UserSerializableReplyAttr>::dummy_query_requests =
    std::vector<QueryRequest>();

template <typename UserSerializableReplyAttr>
Maybe<std::string>
IntelligenceQuery<UserSerializableReplyAttr>::genJson() const
{
    {
        std::stringstream str_stream;
        JsonStream json_stream(&str_stream, is_pretty);
        {
            cereal::JSONOutputArchive out_ar(json_stream);
            if (is_bulk) {
                std::vector<BulkQueryRequest> bulk_requests;
                int index = 0;
                for (QueryRequest &request : requests) {
                    bulk_requests.push_back(BulkQueryRequest(request, index++));
                }
                out_ar(cereal::make_nvp("queries", bulk_requests));
            } else {
                request.saveToJson(out_ar);
            }
        }

        return str_stream.str();
    }
}

template <typename UserSerializableReplyAttr>
bool
IntelligenceQuery<UserSerializableReplyAttr>::loadJson(const std::string &json)
{
    try {
        std::stringstream in;
        in.str(json);
        try {
            cereal::JSONInputArchive in_ar(in);
            load(in_ar);
        } catch (const Intelligence_IS_V2::IntelligenceException &e) {
            dbgWarning(D_INTELLIGENCE) << "Failed to load query response. Error: " << e.what();
            return false;
        }
        return true;
    } catch (const std::exception &e) {
        return false;
    }
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::load(cereal::JSONInputArchive &ar)
{
    if (is_bulk) {
        IntelligenceQueryBulkResponse<UserSerializableReplyAttr> bulk_response;
        bulk_response.serialize(ar);
        unsigned int error_idx = 0;
        unsigned int valid_idx = 0;
        const auto &valid_response = bulk_response.getValid();
        const auto &errors = bulk_response.getErrors();
        responses.clear();
        responses.reserve(requests.size());
        dbgTrace(D_INTELLIGENCE) << "Received response for bulk request with " << requests.size() << " items";
        for (unsigned int query_idx = 0; query_idx < requests.size(); query_idx++) {
            if (valid_response[valid_idx].getIndex() == query_idx) {
                responses.push_back(valid_response[valid_idx].getResponse());
                dbgTrace(D_INTELLIGENCE) << "Item #" << query_idx << " is valid";
                valid_idx++;
            } else if (error_idx < errors.size() && errors[error_idx].getIndex() == query_idx) {
                responses.emplace_back();
                responses[query_idx].setFailInBulk();
                dbgTrace(D_INTELLIGENCE) << "Item #" << query_idx << " is invalid";
                error_idx++;
            } else {
                dbgWarning(D_INTELLIGENCE)
                    << "Query index was not found neither in valid nor error responses, assuming error";
                responses[query_idx].setFailInBulk();
            }
        }
    } else {
        response.loadFromJson(ar);
    }
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::save(cereal::JSONOutputArchive &ar) const
{
    if (!is_bulk) {
        request.saveToJson(ar);
    } else {
        ar(cereal::make_nvp("queries", requests));
    }
}

template <typename UserSerializableReplyAttr>
std::vector<AssetReply<UserSerializableReplyAttr>>
IntelligenceQuery<UserSerializableReplyAttr>::getData()
{
    return response.getData();
}

template <typename UserSerializableReplyAttr>
std::vector<Maybe<std::vector<AssetReply<UserSerializableReplyAttr>>>>
IntelligenceQuery<UserSerializableReplyAttr>::getBulkData()
{
    std::vector<Maybe<std::vector<AssetReply<UserSerializableReplyAttr>>>> bulk_data;
    bulk_data.reserve(responses.size());
    int index = 0;
    for (const auto &res: responses) {
        if (!res.isValidInBulk()) {
            dbgTrace(D_INTELLIGENCE) << "Request #" << index << " in bulk failed";
            bulk_data.push_back(genError("Received error for request in bulk"));
            index++;
        } else {
            dbgTrace(D_INTELLIGENCE) << "Request #" << index << " in bulk received valid response";
            bulk_data.push_back(res.getData());
            index++;
        }
    }
    return bulk_data;
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::activatePaging()
{
    request.setCursor(Intelligence_IS_V2::CursorState::START, "start");
}

template <typename UserSerializableReplyAttr>
Maybe<Intelligence_IS_V2::CursorState>
IntelligenceQuery<UserSerializableReplyAttr>::getPagingStatus()
{
    if (is_bulk) return genError("Paging not activated in bulk mode");
    if (!request.isPagingActivated()) return genError("Paging not activated");
    return request.getCursorState();
}

template <typename UserSerializableReplyAttr>
ResponseStatus
IntelligenceQuery<UserSerializableReplyAttr>::getResponseStatus()
{
    if (!is_bulk) return response.getResponseStatus();

    if (responses.size() == 0) return ResponseStatus::IN_PROGRESS;
    for (const auto &response_itr : responses) {
        if (response_itr.isValidInBulk() && response_itr.getResponseStatus() == ResponseStatus::IN_PROGRESS) {
            return ResponseStatus::IN_PROGRESS;
        }
    }

    return ResponseStatus::DONE;
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::setRequestCursor(CursorState state, const std::string &value)
{
    request.setCursor(state, value);
}

#endif //__INTELLIGENCE_QUERY_V2_IMPL_H_
