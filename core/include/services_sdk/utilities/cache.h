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

#ifndef __CACHE_H__
#define __CACHE_H__

#include <unordered_map>
#include <chrono>
#include <iterator>
#include <list>

#include "i_time_get.h"
#include "i_mainloop.h"
#include "caching/cache_types.h"
#include "maybe_res.h"

template <typename Key, typename Value>
class BaseTemporaryCache
{
    using microseconds = std::chrono::microseconds;
    using seconds = std::chrono::seconds;
    using const_iterator = typename std::unordered_map<Key, Cache::Holder<Value, Key>>::const_iterator;

public:
    void createEntry(const Key &key);
    void deleteEntry(const Key &key);
    bool doesKeyExists(const Key &key) const;
    Maybe<Key> getKeyEntry(const Key &key) const;
    void clear();
    size_t size() const;

    void startExpiration(const microseconds &expire_length, I_MainLoop *_mainloop=nullptr, I_TimeGet *_timer=nullptr);
    void endExpiration();

    size_t capacity() const;
    void capacity(size_t capacity);

    const_iterator begin() const;
    const_iterator end() const;

protected:
    void checkExpiration();

    std::unordered_map<Key, Cache::Holder<Value, Key>> entries;
    I_TimeGet *timer = nullptr;
    I_MainLoop *mainloop = nullptr;
    I_MainLoop::RoutineID routine = 0;
    microseconds expiration;
    std::list<Key> keys_by_expiration;
    size_t max_cache_size = 0;
};

template <typename Key, typename Value>
class TemporaryCache : public BaseTemporaryCache<Key, Value>
{
    using microseconds = std::chrono::microseconds;
    using BaseTemporaryCache<Key, Value>::entries;
    using BaseTemporaryCache<Key, Value>::timer;
    using BaseTemporaryCache<Key, Value>::expiration;
    using BaseTemporaryCache<Key, Value>::keys_by_expiration;
    using BaseTemporaryCache<Key, Value>::max_cache_size;

public:
    bool emplaceEntry(const Key &key, const Value &val);
    bool emplaceEntry(const Key &key, Value &&val);
    Value & getEntry(const Key &key);
    Maybe<Value, void> getEntry(const Key &key) const;
    microseconds getEntryTimeLeft(const Key &key);
};

template <typename Key>
class TemporaryCache<Key, void> : public BaseTemporaryCache<Key, void>
{
};

#include "caching/cache_impl.h"

#endif // __CACHE_H__
