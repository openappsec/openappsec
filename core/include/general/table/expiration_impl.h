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

#ifndef __EXPIRATION_IMPL_H__
#define __EXPIRATION_IMPL_H__

#ifndef __TABLE_IMPL_H__
#error "expiration_impl.h should not be included directly"
#endif // __TABLE_IMPL_H__

template <typename Key>
class Table<Key>::Impl::ExpirationEntry
{
public:
    ExpirationEntry(std::chrono::microseconds _expire, const Key &_key);
    bool isBeforeTime(std::chrono::microseconds other_expire) const;
    const Key & getKey() const;
    std::chrono::microseconds getExpiration() const;

private:
    std::chrono::microseconds expire;
    Key key;
};

template <typename Key>
Table<Key>::Impl::ExpirationEntry::ExpirationEntry(std::chrono::microseconds _expire, const Key &_key)
        :
    expire(_expire),
    key(_key)
{
}

template <typename Key>
bool
Table<Key>::Impl::ExpirationEntry::isBeforeTime(std::chrono::microseconds other_expire) const
{
    return expire <= other_expire;
}

template <typename Key>
const Key &
Table<Key>::Impl::ExpirationEntry::getKey() const
{
    return key;
}

template <typename Key>
std::chrono::microseconds
Table<Key>::Impl::ExpirationEntry::getExpiration() const
{
    return expire;
}

template <typename Key>
class Table<Key>::Impl::ExpList
        :
    public TableHelper::I_InternalTableExpiration<Key, ExpIter>
{
public:
    ExpIter addExpiration(std::chrono::microseconds expire, const Key &key) override;
    void removeExpiration(const ExpIter &iter) override;
    bool shouldExpire(std::chrono::microseconds expire) const;
    const Key & getEarliest() const;

private:
    std::list<ExpirationEntry> list;
};

template <typename Key>
typename Table<Key>::Impl::ExpIter
Table<Key>::Impl::ExpList::addExpiration(std::chrono::microseconds expire, const Key &key)
{
    // The list is ordered from the highest value (in the far future) to the lowest (in the near future).
    // So we scan the list to enter before the first vlaue that is smaller than us (typically, the first one).
    for (auto iter = list.begin(); iter != list.end(); iter++) {
        if (iter->isBeforeTime(expire)) {
            return list.emplace(iter, expire, key);
        }
    }
    // There was no value that is closer to the current time, so it should be placed in at the end of the list.
    return list.emplace(list.end(), expire, key);
}

template <typename Key>
void
Table<Key>::Impl::ExpList::removeExpiration(const ExpIter &iter)
{
    list.erase(iter);
}

template <typename Key>
bool
Table<Key>::Impl::ExpList::shouldExpire(std::chrono::microseconds expire) const
{
    if (list.empty()) return false;
    return list.back().isBeforeTime(expire);
}

template <typename Key>
const Key &
Table<Key>::Impl::ExpList::getEarliest() const
{
    dbgAssert(!list.empty()) << "Cannot access the earliest member of an empty list";
    return list.back().getKey();
}

#endif // __EXPIRATION_IMPL_H__
