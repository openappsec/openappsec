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

#include "intelligence_is_v2/intelligence_response.h"

using namespace std;
using namespace Intelligence;

Maybe<void>
Response::load()
{
    try {
        stringstream in;
        in.str(json_response);
        cereal::JSONInputArchive in_ar(in);
        if (is_bulk) {
            IntelligenceQueryBulkResponse bulk_response;
            bulk_response.serialize(in_ar);
            unsigned int error_idx = 0;
            unsigned int valid_idx = 0;
            const auto &valid_response = bulk_response.getValid();
            const auto &errors = bulk_response.getErrors();
            responses.clear();
            responses.reserve(size);
            dbgTrace(D_INTELLIGENCE) << "Received response for bulk request with " << size << " items";
            for (unsigned int query_idx = 0; query_idx < size; query_idx++) {
                if (valid_idx < valid_response.size() && valid_response[valid_idx].getIndex() == query_idx) {
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
            single_response.serialize(in_ar);
        }
    } catch(const std::exception &e) {
        return genError("Load common data failed. Error: " + string(e.what()));
    }
    return {};
}

Maybe<void>
Response::loadInvalidations()
{
    try {
        stringstream in;
        in.str(json_response);
        cereal::JSONInputArchive in_ar(in);
        in_ar(cereal::make_nvp("invalidations", invalidations));
    } catch(const std::exception &e) {
        return genError("Load invalidations failed. Error: " + string(e.what()));
    }
    return {};
}

Intelligence_IS_V2::ResponseStatus
Response::getResponseStatus() const
{
    if (!is_bulk) return single_response.getResponseStatus();

    if (responses.size() == 0) return ResponseStatus::IN_PROGRESS;
    for (const auto &response_itr : responses) {
        if (response_itr.isValidInBulk() && response_itr.getResponseStatus() == ResponseStatus::IN_PROGRESS) {
            return ResponseStatus::IN_PROGRESS;
        }
    }

    return ResponseStatus::DONE;
}
