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

#include "intelligence_is_v2/bulk_query_response_v2.h"

using namespace std;

void
BulkResponseError::serialize(cereal::JSONInputArchive &ar)
{
    ar(
        cereal::make_nvp("index", index),
        cereal::make_nvp("statusCode", status_code),
        cereal::make_nvp("message", message)
    );
}

void
ValidBulkQueryResponse::serialize(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("index", index), cereal::make_nvp("response", response));
}

void
IntelligenceQueryBulkResponse::serialize(cereal::JSONInputArchive &ar)
{
    ar(cereal::make_nvp("errors", errors));
    ar(cereal::make_nvp("queriesResponse", valid_responses));
}
