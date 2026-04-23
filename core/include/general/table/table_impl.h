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

#ifndef __TABLE_IMPL_H__
#define __TABLE_IMPL_H__

#ifndef __TABLE_H__
#error "table_impl.h should not be included directly"
#endif // __TABLE_H__

#include <sstream>
#include <memory>
#include <iostream>

#include "time_print.h"
#include "debug.h"
#include "singleton.h"
#include "context.h"
#include "table/table_helpers.h"
#include "table/table_list.h"
#include "table/opaque_repo.h"
#include "config.h"

USE_DEBUG_FLAG(D_TABLE);

template <typename Key>
class Table<Key>::Impl
        :
    public TableHelper::Constant,
    public TableHelper::I_InternalTableList<TableHelper::KeyNodePtr<Key>>,
    public Singleton::Provide<I_Table>::From<Table<Key>>,
    public Singleton::Provide<I_TableSpecific<Key>>::template From<Table<Key>>
{
    class ExpirationEntry;
    using ExpIter = typename std::list<ExpirationEntry>::iterator;
    class ExpList;

    class Entry;
    using EntryRef = std::shared_ptr<Entry>;
    using EntryMap = std::unordered_map<Key, EntryRef>;

public:
    void init();
    void fini();

    // I_InternalTableControl methods
    void removeKey(const TableHelper::KeyNodePtr<Key> &key) override;

    // I_Table protected methods
    bool              hasState   (const std::type_index &index) const                                   override;
    bool              createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr) override;
    bool              deleteState(const std::type_index &index)                                         override;
    TableOpaqueBase * getState   (const std::type_index &index)                                         override;

    // I_Table public methods
    void              setExpiration(std::chrono::milliseconds expire)       override;
    bool              doesKeyExists()                                 const override;
    std::string       keyToString  ()                                 const override;
    TableIter         begin        ()                                 const override;
    TableIter         end          ()                                 const override;

    // I_TableSpecific methods
    bool              hasEntry      (const Key &key)                                                       override;
    bool              createEntry   (const Key &key, std::chrono::microseconds expire)                     override;
    bool              deleteEntry   (const Key &key)                                                       override;
    bool              addLinkToEntry(const Key &key, const Key &link)                                      override;
    uint              count         ()                                                                     override;
    void              expireEntries ()                                                                     override;
    bool              setActiveKey  (const Key &key)                                                       override;
    void              unsetActiveKey()                                                                     override;
    Maybe<Key, void>  getCurrentKey ()                                                               const override;
    void              saveEntry     (TableIter iter, SyncMode mode, cereal::BinaryOutputArchive &ar) const override;
    void              loadEntry     (cereal::BinaryInputArchive &ar)                                       override;

private:
    EntryRef getCurrEntry() const;

    // Members
    EntryMap                  entries;
    ExpList                   expiration;
    TableHelper::KeyList<Key> list;
    Context                   ctx;
    // Interfaces
    I_TimeGet     *timer    = nullptr;
    I_Environment *env      = nullptr;
};

#include "table/entry_impl.h"
#include "table/expiration_impl.h"

template <typename Key>
void
Table<Key>::Impl::init()
{
    env = Singleton::Consume<I_Environment>::by<Table<Key>>();
    timer = Singleton::Consume<I_TimeGet>::by<Table<Key>>();
    auto mainloop  = Singleton::Consume<I_MainLoop>::by<Table<Key>>();
    mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::Timer,
        std::chrono::milliseconds(100),
        [&] () { expireEntries(); },
        "Delete expired table entries"
    );
}

template <typename Key>
void
Table<Key>::Impl::fini()
{
    while (count() > 0) {
        deleteEntry(expiration.getEarliest());
    }

    env = nullptr;
    timer = nullptr;
}

template <typename Key>
void
Table<Key>::Impl::removeKey(const TableHelper::KeyNodePtr<Key> &key)
{
    if (!key) {
        dbgError(D_TABLE) << "Function called without a key";
        return;
    }
    auto iter = entries.find(key->getKey());
    if (iter == entries.end()) {
        dbgError(D_TABLE) << "Trying to remove a non-existing key " << key;
        return;
    }
    dbgTrace(D_TABLE) << "Removing the key " << key;
    entries.erase(iter);
    list.removeKey(key);
}

template <typename Key>
bool
Table<Key>::Impl::hasState(const std::type_index &index) const
{
    dbgTrace(D_TABLE) << "Checking if there is a state of type " << index.name();
    auto entry = getCurrEntry();
    if (!entry) return false;
    return entry->hasState(index);
}

template <typename Key>
bool
Table<Key>::Impl::createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr)
{
    auto ent = getCurrEntry();
    if (ent == nullptr) {
        dbgError(D_TABLE) << "Trying to create a state without an entry";
        return false;
    }
    return ent->createState(index, std::move(ptr));
}

template <typename Key>
bool
Table<Key>::Impl::deleteState(const std::type_index &index)
{
    auto ent = getCurrEntry();
    if (ent) return ent->delState(index);
    return false;
}

template <typename Key>
TableOpaqueBase *
Table<Key>::Impl::getState(const std::type_index &index)
{
    auto ent = getCurrEntry();
    dbgTrace(D_TABLE) << "Getting a state of type " << index.name();
    if (!ent) return nullptr;
    return ent->getState(index);
}

template <typename Key>
void
Table<Key>::Impl::setExpiration(std::chrono::milliseconds expire)
{
    auto ent = getCurrEntry();
    if (!ent) return;
    auto curr_time = timer->getMonotonicTime();
    ent->setExpiration(curr_time + expire);
}

template <typename Key>
bool
Table<Key>::Impl::doesKeyExists() const
{
    auto key = env->get<Key>(primary_key);
    if (!key.ok()) return false;
    return entries.find(key.unpack()) != entries.end();
}

template <typename Key>
std::string
Table<Key>::Impl::keyToString() const
{
    auto key = env->get<Key>(primary_key);
    if (!key.ok()) return "";
    std::ostringstream os;
    os << key.unpack();
    return os.str();
}

template <typename Key>
TableIter
Table<Key>::Impl::begin() const
{
    return TableIter(list.begin());
}

template <typename Key>
TableIter
Table<Key>::Impl::end() const
{
    return TableIter(list.end());
}

template <typename Key>
bool
Table<Key>::Impl::hasEntry(const Key &key)
{
    return entries.find(key) != entries.end();
}

template <typename Key>
bool
Table<Key>::Impl::createEntry(const Key &key, std::chrono::microseconds expire)
{
    if (entries.find(key) != entries.end()) {
        dbgWarning(D_TABLE) << "Trying to recreate an entry with the key " << key;
        return false;
    }
    auto curr_time = timer->getMonotonicTime();
    auto expire_time = curr_time + expire;
    dbgTrace(D_TABLE) << "Creating an entry with the key " << key << " for " << expire;
    entries.emplace(key, std::make_shared<Entry>(this, &expiration, key, list.addKey(key), expire_time));
    return true;
}

template <typename Key>
bool
Table<Key>::Impl::deleteEntry(const Key &key)
{
    auto iter = entries.find(key);
    if (iter == entries.end()) {
        dbgWarning(D_TABLE) << "Trying to delete a non-existing entry of the key " << key;
        return false;
    }
    auto ent = iter->second; // Important, since we don't want the entry to disappear before we leave the function.
    dbgTrace(D_TABLE) << "Deleting an entry of the key " << key;
    ent->removeSelf();
    return true;
}

template <typename Key>
bool
Table<Key>::Impl::addLinkToEntry(const Key &key, const Key &link)
{
    auto iter = entries.find(key);
    if (iter == entries.end()) {
        dbgWarning(D_TABLE) << "No entry, to which to add a key";
        return false;
    }
    bool success = entries.emplace(link, iter->second).second;
    if (!success) {
        dbgWarning(D_TABLE) << "Attempting to re-enter a key " <<link;
        return false;
    }
    dbgTrace(D_TABLE) << "Linking the key " << link << " with the key " << key;
    iter->second->addKey(link, list.addKey(link));
    return true;
}

template <typename Key>
uint
Table<Key>::Impl::count()
{
    return entries.size();
}

template <typename Key>
void
Table<Key>::Impl::expireEntries()
{
    auto curr_time = timer->getMonotonicTime();
    while (expiration.shouldExpire(curr_time)) {
        auto key = expiration.getEarliest();
        ScopedContext ctx;
        ctx.registerValue(primary_key, key);
        deleteEntry(key);
    }
}

template <typename Key>
bool
Table<Key>::Impl::setActiveKey(const Key &key)
{
    auto entry = entries.find(key);
    if (entry == entries.end()) return false;
    ctx.registerValue(primary_key, key);
    ctx.activate();
    entry->second->uponEnteringContext();
    return true;
}

template <typename Key>
void
Table<Key>::Impl::unsetActiveKey()
{
    auto entry = getCurrEntry();
    if (entry == nullptr) {
        dbgError(D_TABLE) << "Unsetting the active key when there is no active entry";
        return;
    }
    entry->uponLeavingContext();
    ctx.deactivate();
}

template <typename Key>
Maybe<Key, void>
Table<Key>::Impl::getCurrentKey() const
{
    return env->get<Key>(primary_key);
}

template <typename Key>
typename Table<Key>::Impl::EntryRef
Table<Key>::Impl::getCurrEntry() const
{
    auto key = env->get<Key>(primary_key);
    if (!key.ok()) {
        dbgTrace(D_TABLE) << "Key was not found";
        return nullptr;
    }
    auto iter = entries.find(key.unpack());
    if (iter == entries.end()) {
        dbgTrace(D_TABLE) << "No entry matches the key " << key.unpack();
        return nullptr;
    }
    return iter->second;
}

template <typename Key>
void
Table<Key>::Impl::saveEntry(TableIter iter, SyncMode mode, cereal::BinaryOutputArchive &ar) const
{
    iter.setEntry();
    auto ent = getCurrEntry();
    ar(
        cereal::make_nvp("keys_vec", ent->getKeys()),
        cereal::make_nvp("expire", ent->getExpiration())
    );

    ent->save(ar);

    if (mode == SyncMode::TRANSFER_ENTRY) {
        std::string key = keyToString();
        ent->removeSelf();
        dbgTrace(D_TABLE) << "Key '" << key <<"' was removed";
    }
    iter.unsetEntry();
}

template <typename Key>
void
Table<Key>::Impl::loadEntry(cereal::BinaryInputArchive &ar)
{
    std::vector<Key> keys_vec;
    std::chrono::microseconds expire;

    ar(
        cereal::make_nvp("keys_vec", keys_vec),
        cereal::make_nvp("expire", expire)
    );

    if (keys_vec.size() == 0) {
        dbgError(D_TABLE) << "No Keys to load";
        return;
    }

    if (!createEntry(keys_vec[0], expire)) {
        dbgError(D_TABLE) << "Cannot create a new entry";
        return;
    }

    for (decltype(keys_vec.size()) index=1; index<keys_vec.size(); index++) {
        if (!addLinkToEntry(keys_vec[0], keys_vec[index])) {
            dbgError(D_TABLE) << "Cannot add link to an entry";
            return;
        }
    }

    auto entry_iter = entries.find(keys_vec[0]);
    if (entry_iter == entries.end()) return;
    auto ent = entry_iter->second;
    ent->load(ar);
}

template <typename Key>
Table<Key>::Table() : Component("Table"), pimpl(std::make_unique<Table::Impl>())
{
}

template <typename Key>
Table<Key>::~Table()
{
}

template <typename Key>
void
Table<Key>::init()
{
    pimpl->init();
}

template <typename Key>
void
Table<Key>::fini()
{
    pimpl->fini();
}

template <typename Key>
void
Table<Key>::preload()
{
}

#endif // __TABLE_IMPL_H__
