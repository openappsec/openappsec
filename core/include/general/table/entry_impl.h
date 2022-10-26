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

#ifndef __ENTRY_IMPL_H__
#define __ENTRY_IMPL_H__

#ifndef __TABLE_IMPL_H__
#error "entry_impl.h should not be included directly"
#endif // __TABLE_IMPL_H__

USE_DEBUG_FLAG(D_TABLE);

template <typename Key>
class Table<Key>::Impl::Entry
{
    using KeyNodePtr = TableHelper::KeyNodePtr<Key>;
    using ListInterface = TableHelper::I_InternalTableList<KeyNodePtr> *;
    using ExpirationInterface = TableHelper::I_InternalTableExpiration<Key, ExpIter> *;
    using ms = std::chrono::microseconds;
public:
    Entry(ListInterface _table, ExpirationInterface _expiration, const Key &key, const KeyNodePtr &ptr, ms expire);
    bool hasState(std::type_index index) const;
    bool createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr);
    bool delState(const std::type_index &index);
    TableOpaqueBase * getState(const std::type_index &index);
    void addKey(const Key &key, const KeyNodePtr &ptr);
    void removeSelf();
    void setExpiration(ms expire);
    std::chrono::microseconds getExpiration();
    std::vector<Key> getKeys();
    void uponEnteringContext();
    void uponLeavingContext();

    template <class Archive>
    void save(Archive &ar) const;
    template <class Archive>
    void load(Archive &ar);

private:
    ListInterface table;
    ExpirationInterface expiration;
    std::unordered_map<Key, KeyNodePtr> keys;
    std::unordered_map<std::type_index, std::unique_ptr<TableOpaqueBase>> opaques;
    ExpIter expr_iter;
};

template <typename Key>
Table<Key>::Impl::Entry::Entry(
    ListInterface _table,
    ExpirationInterface _expiration,
    const Key &key,
    const KeyNodePtr &ptr,
    ms expire)
        :
    table(_table),
    expiration(_expiration)
{
    addKey(key, ptr);
    expr_iter = expiration->addExpiration(expire, key);
}

template <typename Key>
bool
Table<Key>::Impl::Entry::hasState(std::type_index index) const
{
    return opaques.count(index) != 0;
}

template <typename Key>
bool
Table<Key>::Impl::Entry::createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr)
{
    if (hasState(index)) {
        dbgError(D_TABLE) << "Failed to recreate a state of type " << index.name();
        return false;
    }

    dbgTrace(D_TABLE) << "Creating a state of type " << index.name();
    return opaques.emplace(index, std::move(ptr)).second;
}

template <typename Key>
bool
Table<Key>::Impl::Entry::delState(const std::type_index &index)
{
    dbgTrace(D_TABLE) << "Deleting state of type " << index.name();
    auto iter = opaques.find(index);
    if (iter == opaques.end()) return false;
    opaques.erase(iter);
    return true;
}

template <typename Key>
TableOpaqueBase *
Table<Key>::Impl::Entry::getState(const std::type_index &index)
{
    auto iter = opaques.find(index);
    if (iter == opaques.end()) return nullptr;
    return iter->second.get();
}

template <typename Key>
void
Table<Key>::Impl::Entry::addKey(const Key &key, const KeyNodePtr &ptr)
{
    keys[key] = ptr;
}

template <typename Key>
void
Table<Key>::Impl::Entry::removeSelf()
{
    expiration->removeExpiration(expr_iter);
    for (auto &iter : keys) {
        table->removeKey(iter.second);
    }
    keys.clear();
    opaques.clear();
}

template <typename Key>
void
Table<Key>::Impl::Entry::setExpiration(ms expire)
{
    expiration->removeExpiration(expr_iter);
    expr_iter = expiration->addExpiration(expire, keys.begin()->first);
}

template <typename Key>
std::chrono::microseconds
Table<Key>::Impl::Entry::getExpiration()
{
    return expr_iter->getExpiration();
}

template <typename Key>
std::vector<Key>
Table<Key>::Impl::Entry::getKeys()
{
    std::vector<Key> keys_vec;
    keys_vec.reserve(keys.size());
    for (auto &iter : keys) {
        keys_vec.emplace_back(iter.first);
    }
    return keys_vec;
}

template <typename Key>
void
Table<Key>::Impl::Entry::uponEnteringContext()
{
    for (auto &opauqe : opaques) {
        opauqe.second->uponEnteringContext();
    }
}

template <typename Key>
void
Table<Key>::Impl::Entry::uponLeavingContext()
{
    for (auto &opauqe : opaques) {
        opauqe.second->uponLeavingContext();
    }
}

template <typename Key>
template <class Archive>
void
Table<Key>::Impl::Entry::save(Archive &ar) const
{
    std::vector<std::string> opaque_names;
    opaque_names.reserve(opaques.size());
    for (auto &iter : opaques) {
        opaque_names.emplace_back(iter.second->nameOpaque());
    }

    ar(cereal::make_nvp("opaque_names", opaque_names));

    for (auto &iter : opaques) {
        // 0 is used currently until supporting versions
        iter.second->saveOpaque(ar, 0);
    }
}

template <typename Key>
template <class Archive>
void
Table<Key>::Impl::Entry::load(Archive &ar)
{
    std::vector<std::string> opaque_names;
    ar(cereal::make_nvp("opaque_names", opaque_names));

    auto &rep = ::cereal::detail::StaticObject<TableOpaqueRep>::getInstance();
    for (auto &iter : opaque_names) {
        auto opaque = rep.getOpaqueByName(iter);
        if (!opaque) {
            dbgTrace(D_TABLE) << "Failed to load synced opaque " << iter;
            return;
        }

        // 0 is used currently until supporting versions
        opaque->loadOpaque(ar, 0);

        if (!createState(typeid(*opaque), move(opaque))) {
            dbgError(D_TABLE) << "Failed to create the state for opaque " << iter;
        }
    }
}

#endif // __ENTRY_IMPL_H__
