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

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReplyAttr>
Maybe<std::string>
IntelligenceQuery<UserSerializableReplyAttr>::genJson() const
{
    {
        std::stringstream out;
        {
            cereal::JSONOutputArchive out_ar(out);
            request.saveToJson(out_ar);
        }
        return out.str();
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
    response.loadFromJson(ar);
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::save(cereal::JSONOutputArchive &ar) const
{
    request.saveToJson(ar);
}

template <typename UserSerializableReplyAttr>
std::vector<AssetReply<UserSerializableReplyAttr>>
IntelligenceQuery<UserSerializableReplyAttr>::getData()
{
    return response.getData();
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
    if (!request.isPagingActivated()) return genError("Paging not activated");
    return request.getCursorState();
}

template <typename UserSerializableReplyAttr>
void
IntelligenceQuery<UserSerializableReplyAttr>::setRequestCursor(CursorState state, const std::string &value)
{
    request.setCursor(state, value);
}

#endif //__INTELLIGENCE_QUERY_V2_IMPL_H_
