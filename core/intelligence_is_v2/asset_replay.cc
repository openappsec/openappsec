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

#include "intelligence_is_v2/asset_reply.h"

using namespace std;

void
IntelligenceQueryResponse::loadFromJson(const std::string &json_response)
{
    std::stringstream in;
    in.str(json_response);
    cereal::JSONInputArchive in_ar(in);
    serialize(in_ar);
}

template <class Archive>
void
IntelligenceQueryResponse::serialize(Archive &ar)
{
    std::string raw_data;
    ar(cereal::make_nvp("status", raw_data), cereal::make_nvp("totalNumAssets", total_num_assets));
    status = Intelligence_IS_V2::convertStringToResponseStatus(raw_data);

    try {
        ar(cereal::make_nvp("cursor", cursor));
    } catch (...) {}
}
