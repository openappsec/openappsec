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

#ifndef __SCOPE_EXIT_H__
#define __SCOPE_EXIT_H__

// Scope Exit - executes some code when an instance of this class falls off scope.
// This is very useful when a clean-up operation is needed due to pre-mature / exception.
// Example usage:
//
//   work_t work;
//   auto guard = scope_guard([&]{ work.rollback(); }); // access to local/class vars allowed in code
//   work.do_work(); // may throw
//   if (!work.success()) return false; // premature exit
//   guard.release();
//   return true;
//
//
// Code taken from N4189 pending standard - www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n4189.pdf
// (with some minor adaptations for C++11)

#include <type_traits> // For ::std::remove_reference

namespace std
{

template <typename EF>
class scope_exit
{
    // private must come first due to use of noexcept in dtor
private:
    EF exit_function;
    bool execute_on_destruction;

public:
    // ctor
    explicit scope_exit(EF &&f) noexcept
            :
        exit_function(::std::move(f)),
        execute_on_destruction{true}
    {}

    // dtor
    ~scope_exit()
    {
        if (execute_on_destruction) this->exit_function();
    }

// LCOV_EXCL_START Reason: coverage upgrade
    // move
    scope_exit(scope_exit &&rhs) noexcept
            :
        exit_function(::std::move(rhs.exit_function)),
        execute_on_destruction{rhs.execute_on_destruction}
    {
        rhs.release();
    }
// LCOV_EXCL_STOP

    void
    release() noexcept
    {
        this->execute_on_destruction = false;
    }

private:
    scope_exit(const scope_exit &) = delete;
    void operator=(const scope_exit &) = delete;
    scope_exit & operator=(scope_exit &&) = delete;
};

template <typename EF>
scope_exit<typename ::std::remove_reference<EF>::type>
make_scope_exit(EF &&exit_function) noexcept
{
    return scope_exit<typename ::std::remove_reference<EF>::type>(::std::forward<EF>(exit_function));
}

} // namespace std

#endif // __SCOPE_EXIT_H__
