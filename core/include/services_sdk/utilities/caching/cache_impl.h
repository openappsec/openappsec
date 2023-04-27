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

#ifndef __CACHE_IMPL_H__
#define __CACHE_IMPL_H__

#ifndef __CACHE_H__
#error cache_impl.h should not be included directly!
#endif // __CACHE_H__

#include "debug.h"

USE_DEBUG_FLAG(D_INFRA);

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::createEntry(const Key &key)
{
    if (doesKeyExists(key)) {
        auto &holder = entries.find(key)->second;
        holder.setNewTime(timer);
        keys_by_expiration.erase(holder.getSelf());
        keys_by_expiration.push_front(key);
        holder.setSelf(keys_by_expiration.begin());
        return;
    }

    auto entry = entries.insert(std::make_pair(key, Cache::Holder<Value, Key>(timer))).first;
    keys_by_expiration.push_front(key);
    entry->second.setSelf(keys_by_expiration.begin());
    if (max_cache_size != 0 && max_cache_size < entries.size()) {
        entries.erase(keys_by_expiration.back());
        keys_by_expiration.pop_back();
    }
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::deleteEntry(const Key &key)
{
    auto entry = entries.find(key);
    if (entry == entries.end()) return;

    keys_by_expiration.erase(entry->second.getSelf());
    entries.erase(entry);
}

template <typename Key, typename Value>
bool
BaseTemporaryCache<Key, Value>::doesKeyExists(const Key &key) const
{
    return entries.find(key) != entries.end();
}

template <typename Key, typename Value>
Maybe<Key>
BaseTemporaryCache<Key, Value>::getKeyEntry(const Key &key) const
{
    for (auto iter = entries.begin(); iter != entries.end(); iter++ ) {
        if (iter->first == key) {
            return iter->first;
        }
    }
    return genError("key not found");
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::clear()
{
    entries.clear();
    keys_by_expiration.clear();
}

template <typename Key, typename Value>
size_t
BaseTemporaryCache<Key, Value>::size() const
{
    return entries.size();
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::startExpiration(
    const microseconds &expire_length,
    I_MainLoop *_mainloop,
    I_TimeGet *_timer)
{
    expiration = expire_length;

    // Assume that all entries before the first expiration expire immediately
    if (timer == nullptr) clear();

    // If we don't get the interfaces, just update the expiration
    if (_mainloop==nullptr || _timer==nullptr) return;
    mainloop = _mainloop;
    timer = _timer;

    if (mainloop->doesRoutineExist(routine)) {
        dbgWarning(D_INFRA) << "Expiration is already active in caching module, just updating the expiration";
        return;
    }

    I_MainLoop::Routine expiration_routine = [&] () { checkExpiration(); };
    routine = mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        seconds(1),
        expiration_routine,
        "Delete expired cache entries"
    );
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::endExpiration()
{
    if (mainloop->doesRoutineExist(routine)) mainloop->stop(routine);
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::checkExpiration()
{
    auto expire_time = timer->getMonotonicTime() - expiration;

    // Currently, we assume that the cache is small enough that we don't need to yield.
    while (!keys_by_expiration.empty()) {
        auto curr_entry = entries.find(keys_by_expiration.back());

        if (!curr_entry->second.isExpired(expire_time)) return;

        entries.erase(curr_entry);
        keys_by_expiration.pop_back();
    }
}

template <typename Key, typename Value>
size_t
BaseTemporaryCache<Key, Value>::capacity() const
{
    return max_cache_size;
}

template <typename Key, typename Value>
void
BaseTemporaryCache<Key, Value>::capacity(size_t capacity)
{
    max_cache_size = capacity;
    if (max_cache_size == 0) return;

    while (entries.size() > max_cache_size) {
        entries.erase(keys_by_expiration.back());
        keys_by_expiration.pop_back();
    }
}

template <typename Key, typename Value>
typename std::unordered_map<Key, Cache::Holder<Value, Key>>::const_iterator
BaseTemporaryCache<Key, Value>::begin() const
{
    return entries.begin();
}

template <typename Key, typename Value>
typename std::unordered_map<Key, Cache::Holder<Value, Key>>::const_iterator
BaseTemporaryCache<Key, Value>::end() const
{
    return entries.end();
}

template <typename Key, typename Value>
bool
TemporaryCache<Key, Value>::emplaceEntry(const Key &key, const Value &val)
{
    if (BaseTemporaryCache<Key, Value>::doesKeyExists(key)) {
        auto &holder = entries.find(key)->second;
        holder.setNewTime(timer);
        keys_by_expiration.erase(holder.getSelf());
        keys_by_expiration.push_front(key);
        holder.setSelf(keys_by_expiration.begin());
        return false;
    }

    auto entry = entries.emplace(key, Cache::Holder<Value, Key>(timer, val)).first;
    keys_by_expiration.push_front(key);
    entry->second.setSelf(keys_by_expiration.begin());
    if (max_cache_size != 0 && max_cache_size < entries.size()) {
        entries.erase(keys_by_expiration.back());
        keys_by_expiration.pop_back();
    }
    return true;
}

template <typename Key, typename Value>
bool
TemporaryCache<Key, Value>::emplaceEntry(const Key &key, Value &&val)
{
    if (BaseTemporaryCache<Key, Value>::doesKeyExists(key)) {
        auto &holder = entries.find(key)->second;
        holder.setNewTime(timer);
        keys_by_expiration.erase(holder.getSelf());
        keys_by_expiration.push_front(key);
        holder.setSelf(keys_by_expiration.begin());
        return false;
    }

    auto entry = entries.emplace(key, Cache::Holder<Value, Key>(timer, std::move(val))).first;
    keys_by_expiration.push_front(key);
    entry->second.setSelf(keys_by_expiration.begin());
    if (max_cache_size != 0 && max_cache_size < entries.size()) {
        entries.erase(keys_by_expiration.back());
        keys_by_expiration.pop_back();
    }
    return true;
}

template <typename Key, typename Value>
Value &
TemporaryCache<Key, Value>::getEntry(const Key &key)
{
    if (!BaseTemporaryCache<Key, Value>::doesKeyExists(key)) BaseTemporaryCache<Key, Value>::createEntry(key);
    return entries.at(key).getValue();
}

template <typename Key, typename Value>
Maybe<Value, void>
TemporaryCache<Key, Value>::getEntry(const Key &key) const
{
    if (!BaseTemporaryCache<Key, Value>::doesKeyExists(key)) return genError(0);
    return entries.at(key).getValue();
}

template <typename Key, typename Value>
std::chrono::microseconds
TemporaryCache<Key, Value>::getEntryTimeLeft(const Key &key)
{
    if (!BaseTemporaryCache<Key, Value>::doesKeyExists(key)) return std::chrono::microseconds(0);
    auto time_in_cache =  timer->getMonotonicTime() - entries.at(key).getTime();
    if (expiration <= time_in_cache) return std::chrono::microseconds(0);
    return expiration - time_in_cache;
}

#endif // __CACHE_IMPL_H__
