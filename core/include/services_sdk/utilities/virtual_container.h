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

#ifndef __VIRTUAL_CONTAINER_H__
#define __VIRTUAL_CONTAINER_H__

#include <string>
#include <tuple>
#include <iterator>

class EndVirtualContainer {};

template <typename Modifier, typename Container, bool NeedsInstance>
class VirtualContainerImpl;

template <typename Modifier, typename Container>
class VirtualContainerImpl<Modifier, Container, false>
{
public:
    class ForwardIterator
    {
    public:
        using value_type = typename Container::value_type;
        using pointer = value_type *;
        using reference = value_type &;
        using iterator_category = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using underlying_iterator = typename Container::const_iterator;

        ForwardIterator(const underlying_iterator &iterator, const underlying_iterator &end)
                :
            curr_iterator(iterator),
            next_iterator(iterator),
            end_iterator(end)
        {
            ++(*this);
        }

        bool
        operator==(const ForwardIterator &other) const
        {
            return curr_iterator == other.curr_iterator;
        }

        bool
        operator!=(const ForwardIterator &other) const
        {
            return !(*this == other);
        }

        const value_type &
        operator*() const
        {
            return curr_value;
        }

        ForwardIterator &
        operator++()
        {
            try {
                if (curr_iterator == end_iterator) return *this;
                curr_iterator = next_iterator;
                std::tie(curr_value, next_iterator) = Modifier::getValueAndNextIter(next_iterator, end_iterator);
            } catch (const EndVirtualContainer &) {
                curr_iterator = end_iterator;
                next_iterator = end_iterator;
            }
            return *this;
        }

    private:
        underlying_iterator curr_iterator;
        underlying_iterator next_iterator;
        underlying_iterator end_iterator;
        value_type curr_value;
    };

    using value_type = typename Container::value_type;
    using const_iterator = ForwardIterator;

    VirtualContainerImpl(const Container &underlying_container)
            :
        underlying_begin(underlying_container.begin()),
        underlying_end(underlying_container.end())
    {
    }

    ForwardIterator begin() const { return ForwardIterator(underlying_begin, underlying_end); }
    ForwardIterator end() const { return ForwardIterator(underlying_end, underlying_end); }

private:
    typename Container::const_iterator underlying_begin;
    typename Container::const_iterator underlying_end;
};

template <typename Modifier, typename Container>
class VirtualContainerImpl<Modifier, Container, true>
{
public:
    class ForwardIterator
    {
    public:
        using value_type = typename Container::value_type;
        using pointer = value_type *;
        using reference = value_type &;
        using iterator_category = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using underlying_iterator = typename Container::const_iterator;

        ForwardIterator(const underlying_iterator &iterator, const underlying_iterator &end)
                :
            curr_iterator(iterator),
            next_iterator(iterator),
            end_iterator(end)
        {
            ++(*this);
        }

        bool
        operator==(const ForwardIterator &other) const
        {
            return curr_iterator == other.curr_iterator && modifier == other.modifier;
        }

        bool
        operator!=(const ForwardIterator &other) const
        {
            return !(*this == other);
        }

        const value_type &
        operator*() const
        {
            return curr_value;
        }

        ForwardIterator &
        operator++()
        {
            try {
                if (curr_iterator == end_iterator) return *this;
                curr_iterator = next_iterator;
                std::tie(curr_value, next_iterator) = modifier.getValueAndNextIter(next_iterator, end_iterator);
            } catch (const EndVirtualContainer &) {
                curr_iterator = end_iterator;
                next_iterator = end_iterator;
            }
            return *this;
        }

    private:
        Modifier modifier;
        underlying_iterator curr_iterator;
        underlying_iterator next_iterator;
        underlying_iterator end_iterator;
        value_type curr_value;
    };

    using value_type = typename Container::value_type;
    using const_iterator = ForwardIterator;

    VirtualContainerImpl(const Container &underlying_container)
            :
        underlying_begin(underlying_container.begin()),
        underlying_end(underlying_container.end())
    {
    }

    ForwardIterator begin() const { return ForwardIterator(underlying_begin, underlying_end); }
    ForwardIterator end() const { return ForwardIterator(underlying_end, underlying_end); }

private:
    typename Container::const_iterator underlying_begin;
    typename Container::const_iterator underlying_end;
};

template <typename Modifier, typename Container>
class VirtualContainer
        :
    public VirtualContainerImpl<
        Modifier,
        Container,
        std::is_member_function_pointer<
            decltype(&Modifier::template getValueAndNextIter<std::string::const_iterator>)
        >::value
    >
{
public:
    VirtualContainer(const Container &str)
            :
        VirtualContainerImpl<
            Modifier,
            Container,
            std::is_member_function_pointer<
                decltype(&Modifier::template getValueAndNextIter<std::string::const_iterator>)
            >::value
        >(str)
    {
    }
};

template <typename ... Modifiers>
class ModifiersAggregator {};

template <typename Modifier, typename Container>
class VirtualContainer<ModifiersAggregator<Modifier>, Container> : public VirtualContainer<Modifier, Container>
{
public:
    VirtualContainer(const Container &str) : VirtualContainer<Modifier, Container>(str) {}
};

template <typename Modifier, typename ... Modifiers,  typename Container>
class VirtualContainer<ModifiersAggregator<Modifier, Modifiers ...>, Container>
        :
    public VirtualContainer<Modifier, VirtualContainer<ModifiersAggregator<Modifiers ...>, Container>>
{
public:
    VirtualContainer(const Container &str)
            :
        VirtualContainer<Modifier, VirtualContainer<ModifiersAggregator<Modifiers ...>, Container>>(str)
    {
    }
};

template <typename Modifier, typename Container>
VirtualContainer<Modifier, Container>
makeVirtualContainer(const Container &str)
{
    return VirtualContainer<Modifier, Container>(str);
}

template <typename Container, typename Modifier, typename ... Args>
struct VirtualContainerType
{
    using Type = VirtualContainer<Modifier, typename VirtualContainerType<Container, Args...>::Type>;
};

template <typename Container, typename Modifier>
struct VirtualContainerType<Container, Modifier>
{
    using Type = VirtualContainer<Modifier, Container>;
};

template <typename FirstModifier, typename SecondModifier, typename ... Args, typename Container>
typename VirtualContainerType<Container, FirstModifier, SecondModifier, Args...>::Type
makeVirtualContainer(const Container &str)
{
    auto virtual_container = makeVirtualContainer<SecondModifier, Args ...>(str);
    return VirtualContainer<FirstModifier, decltype(virtual_container)>(virtual_container);
}

#endif // __VIRTUAL_CONTAINER_H__
