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

#ifndef __READ_ATTRIBUTE_V2_IMPL_H__
#define __READ_ATTRIBUTE_V2_IMPL_H__

#ifndef __READ_ATTRIBUTE_V2_H__
#error read_attribute_v2_impl.h should not be included directly!
#endif // __READ_ATTRIBUTE_V2_H__

#include "debug.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

template <typename UserSerializableReply>
ReadAttribute<UserSerializableReply>::ReadAttribute(const std::string &_key, UserSerializableReply &_data)
        :
    key(_key),
    data(_data)
{}

template <typename UserSerializableReply>
template <typename Archive>
void
ReadAttribute<UserSerializableReply>::serialize(Archive &ar)
{
    dbgTrace(D_INTELLIGENCE) << "Reading asset's attributes";
    try {
        data.serialize(ar, key);
    } catch (const Intelligence_IS_V2::IntelligenceException &e) {
        dbgWarning(D_INTELLIGENCE) << "Failed to read attributes of query response";
        ar.finishNode();

        throw e;
    }
}

template <typename UserSerializableReply>
UserSerializableReply
ReadAttribute<UserSerializableReply>::getData() const
{
    return data;
}

#endif // __READ_ATTRIBUTE_V2_IMPL_H__
