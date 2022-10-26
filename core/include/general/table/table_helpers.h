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

#ifndef __TABLE_HELPERS_H__
#define __TABLE_HELPERS_H__

#ifndef __TABLE_IMPL_H__
#error "table_helpers.h should not be included directly"
#endif // __TABLE_IMPL_H__

#include "context.h"

namespace TableHelper
{

class Constant
{
protected:
    static const std::string primary_key;
};

template <typename KeyPtr>
class I_InternalTableList
{
public:
    virtual void removeKey(const KeyPtr &key) = 0;

protected:
    ~I_InternalTableList() {}
};

template <typename Key, typename ExpIter>
class I_InternalTableExpiration
{
public:
    virtual ExpIter addExpiration(std::chrono::microseconds expire, const Key &key) = 0;
    virtual void removeExpiration(const ExpIter &iter) = 0;

protected:
    ~I_InternalTableExpiration() {}
};

} // TableHelper

#endif // __TABLE_HELPERS_H__
