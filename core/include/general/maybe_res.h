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

#ifndef __MAYBE_RES_H__
#define __MAYBE_RES_H__

#include <string>
#include <ostream>

#include "common.h"
#include "debug.h"
#include "tostring.h"

template <typename Err>
class Error
{
    template <typename T, typename TErr>
    friend class Maybe;

public:
    template<typename... Args>
    Error(Args&&... args) : err(std::forward<Args>(args)...) {}

    bool
    operator==(const Error &other) const
    {
        return err == other.err;
    }

    template<class Archive>
    void
    serialize(Archive &ar, uint32_t)
    {
        ar(err);
    }

    static constexpr uint32_t getSerializationVersion() { return 0; }

private:
    Err err;
};

template <>
class Error<void>
{
    template <typename T, typename TErr>
    friend class Maybe;

public:
    template<typename... Args> Error(Args&&...) {}

    bool operator==(const Error &) const { return true; }

    template<class Archive> void serialize(Archive &ar, uint32_t) {}
};

// Wrapper templated functions, useful for creating Error class since the templating matching for them is better
template <typename Err, typename... Args>
Error<Err>
genError(Args&&... args)
{
    return Error<Err>(std::forward<Args>(args)...);
}

template <typename Err>
Error<Err>
genError(Err err)
{
    return Error<Err>(std::forward<Err>(err));
}

template <typename T, typename TErr = std::string>
class Maybe
{
public:
    // Constructors from error or from value
    Maybe(const Error<TErr> &_err)     : set(false), err(_err) {}
    Maybe(Error<TErr> &&_err)          : set(false), err(std::move(_err)) {}
    Maybe(const T &_val)               : set(true), val(_val) {}
    Maybe(T &&_val)                    : set(true), val(std::move(_val)) {}

    // Constructors from another error class (which is convertible to TErr)
    template<typename OTErr>
    Maybe(const Error<OTErr> &_err)    : set(false), err(_err.err) {}
    template<typename OTErr>
    Maybe(Error<OTErr> &&_err)         : set(false), err(std::move(_err.err)) {}

    // Constructors from another maybe class (if types are convertible)
    template<typename OT, typename OTErr>
    Maybe(const Maybe<OT, OTErr> &m)   : set(m.ok())
    {
        if (set) {
            new (&val) T(m.unpack());
        } else {
            new (&err) Error<TErr>(m.getErr());
        }
    }

    template<typename OT, typename OTErr>
    Maybe(Maybe<OT, OTErr> &&m)        : set(m.ok())
    {
        if (set) {
            new (&val) T(m.unpackMove());
        } else {
            new (&err) Error<TErr>(m.getErr());
        }
    }

    Maybe(const Maybe &m);
    Maybe(Maybe &&m);
    ~Maybe();

    // Comparison operators
    bool operator==(const Maybe &other) const;
    bool operator!=(const Maybe &other) const { return !(*this==other); }

    // Assignment - you can assing a new value, a new error, or a Maybe containing either
    Maybe & operator=(const T &val);
    Maybe & operator=(T &&val);
    template<typename OTErr>
    Maybe & operator=(const Error<OTErr> &err);
    template<typename OTErr>
    Maybe & operator=(Error<OTErr> &&err);
    Maybe & operator=(const Maybe &other);
    Maybe & operator=(Maybe &&other);

    // Looking inside. Will assert if trying to get value/error when you have the other.
    // ok                 - do we have a value (true) or error (false)?
    // unpack/dereference - get the inner value.
    // getErr             - get the error.
    // passErr            - get the wrapper for the error, used for forwarding errors between different kinds of Maybes
    // unpackMove         - get an R-value reference to the inner value.
    bool                ok()         const { return set; }
    const T &           unpack()     const;
// LCOV_EXCL_START Reason: This function is tested in maybe_res_ut but marked as untested
    const T &           operator*()  const { return unpack(); }
// LCOV_EXCL_STOP
    const T *           operator->() const { return &unpack(); }
    T       &&          unpackMove();
    TErr                getErr()     const;
    const Error<TErr> & passErr()    const;

    // Customized unpack & verify - throw the requested exception type on failure
    template <class Exp, typename Aggregator = ToString, typename... Args>
    void verify(Args... args) const;
    template <class Exp, typename Aggregator = ToString, typename... Args>
    const T & unpack(Args... args) const;

    std::ostream & print(std::ostream &os) const;

    template<class Archive>
    void
    save(Archive &ar, uint32_t) const
    {
        ar(set);
        if (set) {
            ar(val);
        } else {
            ar(err);
        }
    }

    template<class Archive>
    void
    load(Archive &ar, uint32_t)
    {
        bool temp_set;
        ar(temp_set);
        if (temp_set) {
            T temp_val;
            ar(temp_val);
            *this = temp_val;
        } else {
            Error<TErr> temp_err;
            ar(temp_err);
            *this = temp_err;
        }
    }

    static constexpr uint32_t getSerializationVersion() { return 0; }

private:
    bool set;
    union {
        T val;
        Error<TErr> err;
    };
};

template <typename TErr>
class Maybe<void, TErr>
{
    class Nothing
    {
    };
public:
    // Since void isn't a value that we can construct from, we use default constructor instead.
    Maybe()                            : maybe(Nothing()) {}

    // Constructors from error
    Maybe(const Error<TErr> &_err)     : maybe(_err) {}
    Maybe(Error<TErr> &&_err)          : maybe(std::move(_err)) {}

    // Constructors from another error class (which is convertible to TErr)
    template<typename OTErr>
    Maybe(const Error<OTErr> &_err)    : maybe(_err) {}
    template<typename OTErr>
    Maybe(Error<OTErr> &&_err)         : maybe(std::move(_err)) {}

    Maybe(const Maybe &) = default;
    Maybe(Maybe &&) = default;
    ~Maybe() {}

    // Comparison operators
    bool operator==(const Maybe &other) const { return maybe == other.maybe; }
    bool operator!=(const Maybe &other) const { return !(*this==other); }

    // Assignment - you can assing a new error, or a Maybe containing either error or `void`
    template<typename OTErr>
    Maybe & operator=(const Error<OTErr> &err) { maybe = err; return *this; }
// LCOV_EXCL_START Reason: coverage upgrade
    template<typename OTErr>
    Maybe & operator=(Error<OTErr> &&err)      { maybe = std::move(err); return *this; }
// LCOV_EXCL_STOP
    Maybe & operator=(const Maybe &other)      { maybe = other.maybe; return *this; }
    Maybe & operator=(Maybe &&other)           { maybe = std::move(other.maybe); return *this; }

    // Looking inside. Will assert if trying to get error when you have a `void`.
    // ok                 - do we have a `void` (true) or error (false)?
    // getErr             - get the error.
    // passErr            - get the wrapper for the error, used for forwarding errors between different kinds of Maybes
    bool                ok()      const { return maybe.ok();      }
    TErr                getErr()  const { return maybe.getErr();  }
    const Error<TErr> & passErr() const { return maybe.passErr(); }

    // Customized verify - throw the requested exception type on failure
    template <typename... Args>
    void verify(Args... args) const { maybe.verify(std::forward(args)...); }

    std::ostream &
    print(std::ostream &os) const
    {
        if (ok()) return os << "Value()";
        return os << "Error(" << getErr() << ")";
    }

    template<class Archive>
    void
    serialize(Archive &ar)
    {
        ar(maybe);
    }

private:
    Maybe<Nothing, TErr> maybe;
};

//
// Method Implementations
//

template <typename T, typename TErr>
Maybe<T, TErr>::Maybe(const Maybe<T, TErr> &m)
        :
    set(m.set)
{
    if (set) {
        new (&val) T(m.val);
    } else {
        new (&err) Error<TErr>(m.err);
    }
}

template <typename T, typename TErr>
Maybe<T, TErr>::Maybe(Maybe<T, TErr> &&m)
        :
    set(m.set)
{
    if (set) {
        new (&val) T(std::move(m.val));
    } else {
        new (&err) Error<TErr>(std::move(m.err));
    }
}

template <typename T, typename TErr>
Maybe<T, TErr>::~Maybe()
{
    if (set) {
        val.~T();
    } else {
        err.~Error<TErr>();
    }
}

template <typename T, typename TErr>
bool
Maybe<T, TErr>::operator==(const Maybe<T, TErr> &other) const
{
    if (set != other.set) return false;
    if (set) {
        return val == other.val;
    } else {
        return err == other.err;
    }
}


template <typename T, typename TErr>
const T &
Maybe<T, TErr>::unpack() const
{
    dbgAssert(set) << "Maybe value is not set";
    return val;
}

template <typename T, typename TErr>
T &&
Maybe<T, TErr>::unpackMove()
{
    dbgAssert(set) << "No value to be moved";
    return std::move(val);
}

template <typename T, typename TErr>
TErr
Maybe<T, TErr>::getErr() const
{
    dbgAssert(!set) << "Maybe value is set";
    return err.err;
}

template <typename T, typename TErr>
const Error<TErr> &
Maybe<T, TErr>::passErr() const
{
    dbgAssert(!set) << "Maybe value is set";
    return err;
}

template <typename T, typename TErr>
template <class Exp, typename Aggregator, typename... Args>
void
Maybe<T, TErr>::verify(Args... args) const
{
    if (!set) throw Exp(Aggregator(std::forward<Args>(args)..., err.err));
}

template <typename T, typename TErr>
template <class Exp, typename Aggregator, typename... Args>
const T &
Maybe<T, TErr>::unpack(Args... args) const
{
    if (!set) throw Exp(Aggregator(std::forward<Args>(args)..., err.err));
    return val;
}

template <typename T, typename TErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(const T &_val)
{
    if (set) {
        val = _val;
    } else {
        err.~Error<TErr>();
        set = true;
        new (&val) T(_val);
    }
    return *this;
}

template <typename T, typename TErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(T &&_val)
{
    if (set) {
        val = std::move(_val);
    } else {
        err.~Error<TErr>();
        set = true;
        new (&val) T(std::move(_val));
    }
    return *this;
}

template <typename T, typename TErr>
template<typename OTErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(const Error<OTErr> &_err)
{
    if (!set) {
        err = _err.err;
    } else {
        val.~T();
        set = false;
        new (&err) Error<TErr>(_err.err);
    }
    return *this;
}

template <typename T, typename TErr>
template<typename OTErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(Error<OTErr> &&_err)
{
    if (!set) {
        err = std::move(_err.err);
    } else {
        val.~T();
        set = false;
        new (&err) Error<TErr>(std::move(_err.err));
    }
    return *this;
}

template <typename T, typename TErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(const Maybe<T, TErr> &other)
{
    if (other.set) {
        *this = other.val;
    } else {
        *this = other.err;
    }
    return *this;
}

template <typename T, typename TErr>
Maybe<T, TErr> &
Maybe<T, TErr>::operator=(Maybe<T, TErr> &&other)
{
    if (other.set) {
        *this = std::move(other.val);
    } else {
        *this = std::move(other.err);
    }
    return *this;
}

template <typename T, typename TErr>
std::ostream &
Maybe<T, TErr>::print(std::ostream &os) const
{
    if (ok()) return os << "Value(" << unpack() << ")";
    return os << "Error(" << getErr() << ")";
}

// Formatting operator. Prints either the value or the error.

template <typename T, typename TErr>
std::ostream &
operator<<(std::ostream &os, const Maybe<T, TErr> &maybe)
{
    return maybe.print(os);
}

#endif // __MAYBE_RES_H__
