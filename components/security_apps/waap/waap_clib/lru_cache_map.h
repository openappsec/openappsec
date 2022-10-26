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

#pragma once

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/member.hpp>

template<typename KeyType, typename ValueType>
class LruCacheMap {
public:
    // Type that should be passed to the insert() method
    typedef std::pair<KeyType, ValueType> value_type;
private:
    struct TagQueue {};
    struct TagHash {};

    // Multi-Index container implementing both queue and hashmap
    typedef boost::multi_index::multi_index_container<
        value_type,
        boost::multi_index::indexed_by<
            // Interface #0 (default) - sequenced (std::list)
            boost::multi_index::sequenced<
                boost::multi_index::tag<TagQueue>
            >,
            // Interface #1 - hashed (std::unordered_map)
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<TagHash>,
                boost::multi_index::member<
                    value_type,
                    KeyType,
                    &value_type::first // hash by the key
                >
            >
        >
    > container_type;

    typedef typename container_type::template index<TagQueue>::type container_queue_index_type;
    typedef typename container_type::template index<TagHash>::type container_hash_index_type;
public:
    // Allow iteration
    typedef typename container_type::template index<TagQueue>::type::iterator iterator;
    typedef typename container_type::template index<TagQueue>::type::const_iterator const_iterator;
    iterator begin() { return m_queueIndex.begin(); }
    iterator end() { return m_queueIndex.end(); }
    const_iterator cbegin() const { return m_queueIndex.cbegin(); }
    const_iterator cend() const { return m_queueIndex.cend(); }

    // Container constructor
    LruCacheMap(int capacity)
    :m_capacity(capacity),
    m_queueIndex(m_container.template get<TagQueue>()),
    m_hashIndex(m_container.template get<TagHash>())
    {}

    // Get capacity
    std::size_t capacity() const { return m_capacity; }
    // Get count of entries stored
    std::size_t size() const { return m_queueIndex.size(); }
    // Return true if cache is empty
    bool empty() const { return m_queueIndex.empty(); }
    // Clear the cache
    void clear() { m_queueIndex.clear(); }

    // Check if key exists by quickly looking in a hashmap
    bool exist(const KeyType &key) const {
        return m_hashIndex.find(key) != m_hashIndex.end();
    }

    bool get(const KeyType &key, ValueType &value) const {
        // get the std::unordered_map index
        const auto &found = m_hashIndex.find(key);
        if (found == m_hashIndex.end()) {
            // Value not found. Do not touch the value and return false.
            return false;
        }
        // Value found - fill out the value and return true
        value = found->second;
        return true;
    }

    // Insert entry into an LRU cache
    void insert(const value_type &item) {
        // Try to push a new entry to the front (may be rejected due to the hashed_unique index)
        std::pair<typename container_type::iterator, bool> p = m_queueIndex.push_front(item);
        if (!p.second) {
            // not inserted - entry already existed - relocate the entry to the queue front
            m_queueIndex.relocate(m_queueIndex.begin(), p.first);
        }
        else if (m_queueIndex.size() > m_capacity) {
            // remove old unused entries at queue back to keep entries count under capacity
            m_queueIndex.pop_back();
        }
    }

private:
    std::size_t m_capacity;
    container_type m_container;
    container_queue_index_type &m_queueIndex;
    container_hash_index_type &m_hashIndex;
};
