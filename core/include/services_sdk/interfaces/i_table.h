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

#ifndef __I_TABLE_H__
#define __I_TABLE_H__

#include <chrono>
#include <string>
#include <typeindex>

#include "table/opaque_basic.h"
#include "table_iter.h"
#include "maybe_res.h"
#include "cereal/archives/binary.hpp"

enum class SyncMode
{
    DUPLICATE_ENTRY,
    TRANSFER_ENTRY
};

class I_Table
{
public:
    template <typename Opaque>
    bool hasState() const;

    template <typename Opaque, typename ...Args>
    bool createState(Args ...args);

    template <typename Opaque>
    void deleteState();

    template <typename Opaque>
    Opaque & getState();

    virtual void        setExpiration(std::chrono::milliseconds expire)      = 0;
    virtual bool        doesKeyExists()                                const = 0;
    virtual std::string keyToString()                                  const = 0;
    virtual TableIter   begin()                                        const = 0;
    virtual TableIter   end()                                          const = 0;

protected:
    ~I_Table() {}

    virtual bool              hasState   (const std::type_index &index) const = 0;
    virtual bool              createState(const std::type_index &index, std::unique_ptr<TableOpaqueBase> &&ptr) = 0;
    virtual bool              deleteState(const std::type_index &index) = 0;
    virtual TableOpaqueBase * getState   (const std::type_index &index) = 0;
};

template <typename Key>
class I_TableSpecific : public I_Table
{
public:
    virtual bool hasEntry      (const Key &key)                                   = 0;
    virtual bool createEntry   (const Key &key, std::chrono::microseconds expire) = 0;
    virtual bool deleteEntry   (const Key &key)                                   = 0;
    virtual bool addLinkToEntry(const Key &key, const Key &link)                  = 0;
    virtual uint count         ()                                                 = 0;
    virtual void expireEntries ()                                                 = 0;

    virtual void saveEntry(TableIter iter, SyncMode mode, cereal::BinaryOutputArchive &ar) const = 0;
    virtual void loadEntry(cereal::BinaryInputArchive &ar)                        = 0;

    virtual bool setActiveKey             (const Key &key)                        = 0;
    virtual void unsetActiveKey           ()                                      = 0;
    virtual Maybe<Key, void> getCurrentKey()  const                                     = 0;

protected:
    ~I_TableSpecific() {}
};

#include "table/i_table_impl.h"

#endif // __I_TABLE_H__
