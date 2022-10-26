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

#ifndef __LISTENER_H__
#error "listener_impl.h should only be included from listener.h"
#endif // __LISTENER_H__

#include <set>
#include <map>
#include <vector>
#include <string>

class BaseListener
{
    using ActivationFunction = void(*)(BaseListener *);

public:
    virtual ~BaseListener() { unregisterListener(); }

    void registerListener();
    void unregisterListener();

protected:
    void setActivation(ActivationFunction act, ActivationFunction deact);

private:
    bool is_registered = false;
    std::set<ActivationFunction> activate;
    std::set<ActivationFunction> deactivate;
};

template <typename EventType, typename ReturnType>
class ListenerImpl : public ListenerImpl<EventType, void>
{
public:
    virtual typename EventType::EventReturnType respond(const EventType &) = 0;
    virtual std::string getListenerName() const = 0;

    virtual void upon(const EventType &event) { query(&event); }

    static std::vector<typename EventType::EventReturnType>
    query(const EventType *event)
    {
        std::vector<typename EventType::EventReturnType> responses;
        for (auto &listener : ListenerImpl<EventType, void>::listeners) {
            responses.push_back(dynamic_cast<ListenerImpl *>(listener)->respond(*event));
        }
        return responses;
    }

    static std::vector<std::pair<std::string, ReturnType>>
    performNamedQuery(const EventType *event)
    {
        std::vector<std::pair<std::string, ReturnType>> responses;
        for (auto &listener : ListenerImpl<EventType, void>::listeners) {
            ListenerImpl *listener_impl = dynamic_cast<ListenerImpl *>(listener);
            responses.emplace_back(listener_impl->getListenerName(), listener_impl->respond(*event));
        }
        return responses;
    }
};

template <typename EventType>
class ListenerImpl<EventType, void> : virtual public BaseListener
{
public:
    ListenerImpl() { setActivation(activate, deactivate); }

    virtual void upon(const EventType &) = 0;

    static void
    notify(const EventType *event)
    {
        for (auto &listener : listeners) {
            dynamic_cast<ListenerImpl *>(listener)->upon(*event);
        }
    }

    static bool empty() { return listeners.empty(); }

protected:
    static std::set<BaseListener *> listeners;

private:
    static void activate(BaseListener *ptr) { listeners.insert(ptr); }
    static void deactivate(BaseListener *ptr) { listeners.erase(ptr); }
};

template <typename EventType> std::set<BaseListener *> ListenerImpl<EventType, void>::listeners;
