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

#ifndef __IMPL_SINGLETON_H__
#define __IMPL_SINGLETON_H__

#ifndef __SINGLETON_H__
#error impl/singleton.h should not be included directly.
#endif // SINGLETON_H__

template <class I_Face>
class Singleton::Provide
{
public:
    template <class Comp>
    class From : public I_Face
    {
        static_assert(
            std::is_base_of<Provide<I_Face>, Comp>::value,
            "Comp class must inherit from Singleton::Provide<I_Face>"
        );
    public:
        From() { Singleton::registerSingleton(typeid(I_Face), this); }
        ~From() { Singleton::unregisterSingleton(typeid(I_Face), this); }
    };

    class Self;

    class SelfInterface : Self, public I_Face
    {
    };
};

template <class I_Face>
class Singleton::Provide<I_Face>::Self : Provide<I_Face>
    {
    public:
        Self() { Singleton::registerSingleton(typeid(I_Face), this); }
        ~Self() { Singleton::unregisterSingleton(typeid(I_Face), this); }
    };

template <class I_Face>
class Singleton::Consume
{
public:
    template <class ConsumingComp>
    static inline I_Face *
    by()
    {
        static_assert(
            std::is_base_of<Consume<I_Face>, ConsumingComp>::value,
            "ConsumingComp class must inherit from Singleton::Consume<I_Face>"
        );
        return get();
    }

    template <class ProvidingComp>
    static inline I_Face *
    from()
    {
        static_assert(
            std::is_base_of<Provide<I_Face>, ProvidingComp>::value,
            "ProvidingComp class must inherit from Singleton::Provide<I_Face>"
        );
        return get();
    }

    template <class ProvidingComp>
    static inline I_Face *
    from(const ProvidingComp &)
    {
        return from<ProvidingComp>();
    }

    template <class Comp>
    static inline I_Face *
    to()
    {
        static_assert(
            std::is_base_of<Consume<I_Face>, Comp>::value || std::is_base_of<Provide<I_Face>, Comp>::value,
            "Component class must declare it relationship to the interface"
        );
        return get();
    }

private:
    static inline I_Face * get() { return Singleton::get<I_Face>(); }
};

template <typename T>
bool
Singleton::exists()
{
    return exists(typeid(T));
}

class Singleton::OwnedSingleton
{
public:
    virtual ~OwnedSingleton() {}
};

template <typename T>
T *
Singleton::getOwned()
{
    return static_cast<T *>(owned_singles[typeid(T)].get());
}

template <typename T>
bool
Singleton::existsOwned()
{
    return owned_singles.count(typeid(T)) != 0;
}

template <typename T, typename ...Args>
void
Singleton::newOwned(Args ...args)
{
    owned_singles[typeid(T)] = std::make_unique<T>(std::forward<Args>(args)...);
}

template <typename T>
void
Singleton::deleteOwned()
{
    owned_singles.erase(typeid(T));
}

template <typename T>
void
Singleton::setOwned(std::unique_ptr<T> &&ptr)
{
    owned_singles[typeid(T)] = std::move(ptr);
}

template <typename T>
T *
Singleton::get()
{
    return static_cast<T *>(get(typeid(T)));
}

template <typename Component, typename Interface>
Interface *
getInterface()
{
    return Singleton::Consume<Interface>::template to<Component>();
}

#endif // __IMPL_SINGLETON_H__
