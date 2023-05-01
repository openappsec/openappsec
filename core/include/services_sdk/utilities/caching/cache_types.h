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

#ifndef __CACHE_TYPES_H__
#define __CACHE_TYPES_H__

#ifndef __CACHE_H__
#error cache_types.h should not be included directly!
#endif // __CACHE_H__

namespace Cache
{

using namespace std::chrono;

template <typename Value, typename Key>
class Holder
{
    using list_iterator = typename std::list<Key>::iterator;

public:
    Holder(I_TimeGet *timer) : time(timer!=nullptr?timer->getMonotonicTime():microseconds(0)) {}
    Holder(I_TimeGet *timer, const Value &_val)
            :
        time(timer!=nullptr?timer->getMonotonicTime():microseconds(0)),
        val(_val)
    {
    }

    Holder(I_TimeGet *timer, Value &&_val)
            :
        time(timer!=nullptr?timer->getMonotonicTime():microseconds(0)),
        val(std::move(_val))
    {
    }

    void setSelf(const list_iterator &iter) { self = iter; }
    list_iterator getSelf() const { return self; }

    void setNewTime(I_TimeGet *timer) { timer != nullptr ? time = timer->getMonotonicTime() : microseconds(0); }
    bool isExpired(const microseconds &expired) const { return time < expired; }
    Value & getValue() { return val; }
    const Value & getValue() const { return val; }
    microseconds getTime() { return time; }

private:
    microseconds time;
    Value val;
    list_iterator self;
};

template <typename Key>
class Holder<void, Key>
{
    using list_iterator = typename std::list<Key>::iterator;

public:
    Holder(I_TimeGet *timer) : time(timer!=nullptr?timer->getMonotonicTime():microseconds(0)) {}

    void setNewTime(I_TimeGet *timer) { timer != nullptr ? time = timer->getMonotonicTime() : microseconds(0); }
    bool isExpired(const microseconds &expired) const { return time < expired; }
    microseconds getTime() { return time; }

    void setSelf(const list_iterator &iter) { self = iter; }
    list_iterator getSelf() const { return self; }

private:
    microseconds time;
    list_iterator self;
};

} // namespace Cache

#endif // __CACHE_TYPES_H__
