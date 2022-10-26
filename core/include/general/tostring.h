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

#ifndef __TOSTRING_H__
#define __TOSTRING_H__

#include <sstream>

class ToString
{
public:
    ToString() {}

    template<typename T, typename... Args>
    ToString(const T &obj, Args... args)
    {
        str << obj << static_cast<std::string>(ToString(std::forward<Args>(args)...));
    }

    template<typename T>
    ToString &
    operator<<(const T &obj)
    {
        str << obj;
        return *this;
    }

    template<typename T>
    bool
    operator==(const T &obj) const
    {
        return *this == ToString(obj);
    }

    template<typename T>
    bool
    operator!=(const T &obj) const
    {
        return *this != ToString(obj);
    }

    bool
    operator==(const ToString &other) const
    {
        return str.str() == other.str.str();
    }

    bool
    operator!=(const ToString &other) const
    {
        return str.str() != other.str.str();
    }

    void reset() { str.str(""); }

    operator std::string() { return str.str(); }

private:
    std::ostringstream str;
};

#endif // __TOSTRING_H__
