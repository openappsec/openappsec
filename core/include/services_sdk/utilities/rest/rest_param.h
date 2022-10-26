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

#ifndef __REST_PARAM_H__
#define __REST_PARAM_H__

template <typename T>
class RestParam
{
public:
    RestParam() : is_active(false) {}
    RestParam(const T &_val) : is_active(true), val(_val) {}

    bool isActive() const { return is_active; }

    void setActive(bool new_active) { is_active = new_active; }

    operator T &()
    {
        dbgAssert(is_active) << "Tried to access a non-existing variable";
        return val;
    }

    operator const T &() const
    {
        dbgAssert(is_active) << "Tried to access a non-existing variable";
        return val;
    }

    T & get() { return val; }

    const T & get() const { return val; }

    T &
    operator=(const T &_val)
    {
        is_active = true;
        val = _val;
        return val;
    }

    T &
    operator=(T &&_val)
    {
        is_active = true;
        val = std::move(_val);
        return val;
    }

private:
    bool is_active;
    T val;
};

#endif // __REST_PARAM_H__
