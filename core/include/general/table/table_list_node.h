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

#ifndef __TABLE_LIST_NODE_H__
#define __TABLE_LIST_NODE_H__

#ifndef __TABLE_IMPL_H__
#error "table_list_node.h should not be included directly"
#endif // __TABLE_IMPL_H__

namespace TableHelper
{

template <typename Key>
class KeyNode
{
public:
    KeyNode(const Key &_key);
    void setNext(const std::shared_ptr<KeyNode> &_next);
    const Key & getKey() const;
    const std::shared_ptr<KeyNode> & getNext() const;
    bool isActive() const;
    void deactivate();

private:
    Key key;
    std::shared_ptr<KeyNode> next;
    bool is_active = true;
};

template <typename Key>
KeyNode<Key>::KeyNode(const Key &_key)
        :
    key(_key)
{
}

template <typename Key>
void
KeyNode<Key>::setNext(const std::shared_ptr<KeyNode> &_next)
{
    next = _next;
}

template <typename Key>
const Key &
KeyNode<Key>::getKey() const
{
    return key;
}

template <typename Key>
const std::shared_ptr<KeyNode<Key>> &
KeyNode<Key>::getNext() const
{
    return next;
}

template <typename Key>
bool
KeyNode<Key>::isActive() const
{
    return is_active;
}

template <typename Key>
void
KeyNode<Key>::deactivate()
{
    is_active = false;
}

template <typename Key> using KeyNodePtr = std::shared_ptr<KeyNode<Key>>;

} // TableHelper

#endif // __TABLE_LIST_NODE_H__
