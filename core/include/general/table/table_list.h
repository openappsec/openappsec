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

#ifndef __TABLE_LIST_H__
#define __TABLE_LIST_H__

#ifndef __TABLE_IMPL_H__
#error "table_list.h should not be included directly"
#endif // __TABLE_IMPL_H__

#include "table/table_list_node.h"
#include "table/table_list_iter.h"
#include "debug.h"

USE_DEBUG_FLAG(D_TABLE);

namespace TableHelper
{

template <typename Key>
class KeyList
{
public:
    KeyNodePtr<Key> addKey(const Key &key);
    void removeKey(const KeyNodePtr<Key> &val);
    std::shared_ptr<I_TableIter> begin() const;
    std::shared_ptr<I_TableIter> end() const;

private:
    KeyNodePtr<Key> first;
    KeyNodePtr<Key> last;
};

template <typename Key>
KeyNodePtr<Key>
KeyList<Key>::addKey(const Key &key)
{
    KeyNodePtr<Key> new_entry = std::make_shared<KeyNode<Key>>(key);
    if (!first) {
        first = new_entry;
    } else {
        last->setNext(new_entry);
    }
    last = new_entry;
    return new_entry;
};

template <typename Key>
void
KeyList<Key>::removeKey(const KeyNodePtr<Key> &val)
{
    val->deactivate();

    if (val == first) {
        first = first->getNext();
        if (last == val) last = first; // `val` was the only member of the list
        return;
    }

    for (auto iter = first; iter != last; iter = iter->getNext()) {
        if (iter->getNext() == val) {
            if (iter->getNext() == last) last = iter;
            iter->setNext(iter->getNext()->getNext());
            return;
        }
    }
    dbgError(D_TABLE) << "Iterator was not found in the table key list";
}

template <typename Key>
std::shared_ptr<I_TableIter>
KeyList<Key>::begin() const
{
    return std::make_shared<KeyNodeIter<Key>>(first);
}

template <typename Key>
std::shared_ptr<I_TableIter>
KeyList<Key>::end() const
{
    return std::make_shared<KeyNodeIter<Key>>(nullptr);
}

} // TableHelper

#endif // __TABLE_LIST_H__
