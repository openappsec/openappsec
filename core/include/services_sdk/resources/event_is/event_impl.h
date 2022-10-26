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

#ifndef __EVENT_H__
#error "event_impl.h sould only be included from event.h"
#endif // __EVENT_H__

#include "listener.h"

template <typename EventType, typename ReturnType>
class EventImpl
{
public:
    using EventReturnType = ReturnType;
    using MyListener = Listener<EventType>;

    void notify() const { MyListener::notify(dynamic_cast<const EventType *>(this)); }

    std::vector<ReturnType> query() const { return MyListener::query(dynamic_cast<const EventType *>(this)); }

    std::vector<std::pair<std::string, ReturnType>>
    performNamedQuery() const
    {
        return MyListener::performNamedQuery(dynamic_cast<const EventType *>(this));
    }

protected:
    virtual ~EventImpl() {} // Makes Event polimorphic, so dynamic_cast will work
};

template <typename EventType>
class EventImpl<EventType, void>
{
public:
    using EventReturnType = void;

    void notify() const { Listener<EventType>::notify(dynamic_cast<const EventType *>(this)); }

protected:
    virtual ~EventImpl() {} // Makes Event polimorphic, so dynamic_cast will work
};
