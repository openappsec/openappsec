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

#ifndef __TABLE_LIST_ITER_H__
#define __TABLE_LIST_ITER_H__

#ifndef __TABLE_IMPL_H__
#error "table_list_iter.h should not be included directly"
#endif // __TABLE_IMPL_H__

#include "context.h"

namespace TableHelper
{

template <typename Key>
class KeyNodeIter : public I_TableIter, public Constant
{
public:
    KeyNodeIter(const KeyNodePtr<Key> &iter);
    void operator++() override;
    void operator++(int) override;
    void setEntry() override;
    void unsetEntry() override;
    void * getUniqueId() const override;

private:
    void moveNext();

    KeyNodePtr<Key> curr;
    Context ctx;
};

template <typename Key>
KeyNodeIter<Key>::KeyNodeIter(const KeyNodePtr<Key> &iter) : curr(iter)
{
}

template <typename Key>
void
KeyNodeIter<Key>::operator++()
{
    moveNext();
}

template <typename Key>
void
KeyNodeIter<Key>::operator++(int)
{
    moveNext();
}

template <typename Key>
void
KeyNodeIter<Key>::setEntry()
{
    if (!curr || !curr->isActive()) return;
    ctx.registerValue(primary_key, curr->getKey());
    ctx.activate();
}

template <typename Key>
void
KeyNodeIter<Key>::unsetEntry()
{
    ctx.deactivate();
}

template <typename Key>
void *
KeyNodeIter<Key>::getUniqueId() const
{
    return curr.get();
}

template <typename Key>
void
KeyNodeIter<Key>::moveNext()
{
    while (curr != nullptr) {
        curr = curr->getNext();
        if (curr != nullptr && curr->isActive()) return;
    }
}

} // TableHelper

#endif // __TABLE_LIST_ITER_H__
