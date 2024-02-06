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
#include <string>
#include <vector>

#include "asset_reply.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"
#include "debug.h"
#include "intelligence_types_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

class BulkResponseError
{
public:
    void serialize(cereal::JSONInputArchive &ar);

    unsigned int getIndex() const { return index; }
    int getStatusCode() const { return status_code; }
    const std::string & getMessage() const { return message; }

private:
    unsigned int index;
    int status_code;
    std::string message;
};

class ValidBulkQueryResponse
{
public:
    void serialize(cereal::JSONInputArchive &ar);

    unsigned int getIndex() const { return index; }
    const IntelligenceQueryResponse & getResponse() const { return response; }

private:
    unsigned int index;
    IntelligenceQueryResponse response;
};

template <typename UserSerializableReplyAttr>
class ValidBulkQueryResponseT : public ValidBulkQueryResponse
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        try {
            ValidBulkQueryResponse::serialize(ar);
        } catch (...) {}
        ar(
            cereal::make_nvp("response", response)
        );
    }

    const IntelligenceQueryResponseT<UserSerializableReplyAttr> & getResponse() const { return response; }

private:
    IntelligenceQueryResponseT<UserSerializableReplyAttr> response;
};

class IntelligenceQueryBulkResponse
{
public:
    void serialize(cereal::JSONInputArchive &ar);

    const std::vector<ValidBulkQueryResponse> & getValid() { return valid_responses; }
    const std::vector<BulkResponseError> & getErrors() { return errors; }
private:
    std::vector<ValidBulkQueryResponse> valid_responses;
    std::vector<BulkResponseError> errors;
};

template <typename UserSerializableReplyAttr>
class IntelligenceQueryBulkResponseT : public IntelligenceQueryBulkResponse
{
public:
    void
    serialize(cereal::JSONInputArchive &ar)
    {
        try {
            IntelligenceQueryBulkResponse::serialize(ar);
        } catch(...) {}
        ar(cereal::make_nvp("queriesResponse", valid_responses));
    }

    const std::vector<ValidBulkQueryResponseT<UserSerializableReplyAttr>> & getValid() { return valid_responses; }

private:
    std::vector<ValidBulkQueryResponseT<UserSerializableReplyAttr>> valid_responses;
};

#endif // __BULK_QUERY_RESPONSE_V2_H__
