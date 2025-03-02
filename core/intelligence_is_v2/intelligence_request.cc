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

#include "intelligence_request.h"
#include "debug.h"
#include "intelligence_comp_v2.h"
#include "intelligence_is_v2/json_stream.h"


using namespace Intelligence;
using namespace std;

USE_DEBUG_FLAG(D_INTELLIGENCE);

static const unsigned int upper_assets_limit = 200;
static const unsigned int upper_confidence_limit = 1000;

Maybe<void>
IntelligenceRequest::checkAssetsLimit() const
{
    for (const QueryRequest &query_request : queries) {
        uint assets_limit = query_request.getAssetsLimit();
        if (0 < assets_limit && assets_limit <= upper_assets_limit) continue;
        dbgTrace(D_INTELLIGENCE)
            << "Assets limit for request is "
            << upper_assets_limit
            << ", requests assets: "
            << assets_limit;
        return genError("Assets limit valid range is of [1, " + to_string(upper_assets_limit) + "]");
    }
    return Maybe<void>();
}

Maybe<void>
IntelligenceRequest::checkMinConfidence() const
{
    for (const QueryRequest &query_request : queries) {
        if (query_request.checkMinConfidence(upper_confidence_limit)) continue;
        dbgTrace(D_INTELLIGENCE) << "Illegal confidence value";
        return genError(
            "Minimum confidence value valid range is of [1, " + std::to_string(upper_confidence_limit) + "]"
        );
    }
    return Maybe<void>();
}

bool
IntelligenceRequest::isPagingActivated() const
{
    if (!isPagingAllowed()) return false;
    return queries.begin()->getCursorState().ok();
}

Maybe<bool>
IntelligenceRequest::isPagingFinished() const
{
    if (!isPagingActivated()) return genError("Paging is not activated");
    return queries.begin()->getCursorState().unpack() == CursorState::DONE;
}

Maybe<Intelligence_IS_V2::CursorState>
IntelligenceRequest::getPagingStatus() const
{
    if (!isPagingAllowed()) return genError("Paging is not allowed");
    return queries.begin()->getCursorState();
}

bool
IntelligenceRequest::isPagingAllowed() const
{
    if (isBulk()) return false;
    return true;
}

Maybe<std::string>
IntelligenceRequest::genJson() const
{
    std::stringstream str_stream;
    JsonStream json_stream(&str_stream, is_pretty);
    {
        cereal::JSONOutputArchive out_ar(json_stream);

        out_ar.setNextName(isBulk() ? "queriesTypes" : "queryTypes");
        out_ar.startNode();
        out_ar(cereal::make_nvp("proxyToCloud", is_proxy));
        out_ar.finishNode();

        if (isBulk()) {
            out_ar.setNextName("queries");
            out_ar.startNode();
            out_ar.makeArray();
            uint index = 0;
            for (const auto &query : queries) {
                out_ar.setNextName(nullptr);
                out_ar.startNode();
                out_ar.setNextName("query");
                out_ar.startNode();
                query.saveToJson(out_ar);
                out_ar.finishNode();
                out_ar(cereal::make_nvp("index", index));
                out_ar.finishNode();
                index++;
            }
            out_ar.finishNode();
        } else {
            queries.begin()->saveToJson(out_ar);
        }
    }

    return str_stream.str();
}
