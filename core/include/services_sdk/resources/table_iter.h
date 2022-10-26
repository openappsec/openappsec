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

#ifndef __TABLE_ITER_H__
#define __TABLE_ITER_H__

#include "i_table_iter.h"

template <typename T>
class Table;

class TableIter
{
public:
    void operator++() { ++(*iter); }
    void operator++(int)  { (*iter)++; }
    bool operator==(const TableIter &other) const { return iter->getUniqueId() == other.iter->getUniqueId(); }
    bool operator!=(const TableIter &other) const { return iter->getUniqueId() != other.iter->getUniqueId(); }
    void setEntry() { iter->setEntry(); }
    void unsetEntry() { iter->unsetEntry(); }

private:
    template <typename Key> friend class Table;
    TableIter(const std::shared_ptr<I_TableIter> &_iter) : iter(_iter) {}

    std::shared_ptr<I_TableIter> iter;
};

#endif // __TABLE_ITER_H__
