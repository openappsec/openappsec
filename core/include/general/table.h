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

#ifndef __TABLE_H__
#define __TABLE_H__

#include <memory>

#include "i_table.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "singleton.h"
#include "component.h"

template <typename Key>
class Table
        :
    public Component,
    Singleton::Provide<I_Table>,
    Singleton::Provide<I_TableSpecific<Key>>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_MainLoop>
{
public:
    Table();
    ~Table();

    void init();
    void fini();
    void preload();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#include "table/table_impl.h"

#endif // __TABLE_H__
