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

#ifndef __TIME_PRINT_H__
#define __TIME_PRINT_H__

#include <ostream>
#include <chrono>

static inline std::ostream &
operator<<(std::ostream &os, const std::chrono::microseconds &time)
{
    return os << time.count() << "usec";
}

static inline std::ostream &
operator<<(std::ostream &os, const std::chrono::milliseconds &time)
{
    return os << time.count() << "ms";
}

static inline std::ostream &
operator<<(std::ostream &os, const std::chrono::seconds &time)
{
    return os << time.count() << "s";
}

static inline std::ostream &
operator<<(std::ostream &os, const std::chrono::minutes &time)
{
    return os << time.count() << "m";
}

static inline std::ostream &
operator<<(std::ostream &os, const std::chrono::hours &time)
{
    return os << time.count() << "h";
}

#endif // __TIME_PRINT_H__
