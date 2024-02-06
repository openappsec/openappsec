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

#ifndef __INTELLIGENCE_RESPONSE_H__
#define __INTELLIGENCE_RESPONSE_H__

#include <chrono>
#include <string>
#include <vector>

#include <maybe_res.h>
#include "asset_reply.h"
#include "bulk_query_response_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

namespace Intelligence
{

class Response
{
public:
    Response() = default;
    Response(const std::string &json_body, size_t size, bool is_bulk)
            :
        json_response(json_body), size(size), is_bulk(is_bulk)
    {}

    Maybe<void> load();
    Intelligence_IS_V2::ResponseStatus getResponseStatus() const;
    const std::string getCursor() const { return single_response.getCursor(); }
    void setJsonResponse(const std::string &jsonResponse) { json_response = jsonResponse; }
    template <typename UserSerializableReplyAttr>
    IntelligenceQueryResponseT<UserSerializableReplyAttr> getSerializableResponse() const
    {
        IntelligenceQueryResponseT<UserSerializableReplyAttr> response;
        response.loadFromJson(json_response);
        return response;
    }

    template <typename UserSerializableReplyAttr>
    std::vector<Maybe<std::vector<AssetReply<UserSerializableReplyAttr>>>>
    getBulkData() const
    {
        std::stringstream in;
        in.str(json_response);
        cereal::JSONInputArchive in_ar(in);

        IntelligenceQueryBulkResponseT<UserSerializableReplyAttr> bulk_response;
        bulk_response.serialize(in_ar);
        unsigned int error_idx = 0;
        unsigned int valid_idx = 0;
        const auto &valid_response = bulk_response.getValid();
        const auto &errors = bulk_response.getErrors();
        std::vector<IntelligenceQueryResponseT<UserSerializableReplyAttr>> serializable_responses;
        serializable_responses.reserve(size);
        dbgTrace(D_INTELLIGENCE) << "Received response for bulk request with " << size << " items";
        for (unsigned int query_idx = 0; query_idx < size; query_idx++) {
            if (valid_idx < valid_response.size() && valid_response[valid_idx].getIndex() == query_idx) {
                serializable_responses.push_back(valid_response[valid_idx].getResponse());
                dbgTrace(D_INTELLIGENCE) << "Item #" << query_idx << " is valid";
                valid_idx++;
            } else if (error_idx < errors.size() && errors[error_idx].getIndex() == query_idx) {
                serializable_responses.emplace_back();
                serializable_responses[query_idx].setFailInBulk();
                dbgTrace(D_INTELLIGENCE) << "Item #" << query_idx << " is invalid";
                error_idx++;
            } else {
                dbgWarning(D_INTELLIGENCE)
                    << "Query index was not found neither in valid nor error responses, assuming error";
                serializable_responses[query_idx].setFailInBulk();
            }
        }
        std::vector<Maybe<std::vector<AssetReply<UserSerializableReplyAttr>>>> bulk_data;
        bulk_data.reserve(serializable_responses.size());
        int index = 0;
        for (const auto &res: serializable_responses) {
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

private:
    std::string json_response;
    std::vector<IntelligenceQueryResponse> responses;
    IntelligenceQueryResponse single_response;
    size_t size = 0;
    bool is_bulk = false;
};

}

#endif // __INTELLIGENCE_RESPONSE_H__
