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

#ifndef __BULK_QUERY_RESPONSE_V2_H__
#define __BULK_QUERY_RESPONSE_V2_H__

#include <sstream>
#include <vector>
#include <string>

#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"

#include "debug.h"
#include "intelligence_types_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

class BulkResponseError
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        ar(
            cereal::make_nvp("index", index),
            cereal::make_nvp("statusCode", status_code),
            cereal::make_nvp("message", message)
        );
    }

    unsigned int getIndex() const { return index; }
    int getStatusCode() const { return status_code; }
    const std::string & getMessage() const { return message; }

private:
    unsigned int index;
    int status_code;
    std::string message;
};

template <typename UserSerializableReplyAttr>
class ValidBulkQueryResponse
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        ar(
            cereal::make_nvp("index", index),
            cereal::make_nvp("response", response)
        );
    }

    unsigned int getIndex() const { return index; }
    const IntelligenceQueryResponse<UserSerializableReplyAttr> & getResponse() const { return response; }

private:
    unsigned int index;
    IntelligenceQueryResponse<UserSerializableReplyAttr> response;
};

template <typename UserSerializableReplyAttr>
class IntelligenceQueryBulkResponse
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        ar(cereal::make_nvp("queriesResponse", valid_responses));
        try {
            ar(cereal::make_nvp("errors", errors));
        } catch(...) {}
    }

    const std::vector<ValidBulkQueryResponse<UserSerializableReplyAttr>> & getValid() { return valid_responses; }
    const std::vector<BulkResponseError> & getErrors() { return errors; }

private:
    std::vector<ValidBulkQueryResponse<UserSerializableReplyAttr>> valid_responses;
    std::vector<BulkResponseError> errors;
};

#endif // __BULK_QUERY_RESPONSE_V2_H__
