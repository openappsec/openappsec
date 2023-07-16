// Copyright (C) 2023 Check Point Software Technologies Ltd. All rights reserved.

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

#include "intelligence_is_v2/json_stream.h"

JsonStream::JsonStream(std::ostream *os, bool is_pretty) : std::ostream(this), os(os), is_pretty(is_pretty) {}

int
JsonStream::overflow(int c)
{
    if (c != std::streambuf::traits_type::eof()) {
        add(std::streambuf::traits_type::to_char_type(c));
    }
    return c;
}

void
JsonStream::emplace(char c)
{
    *os << c;
}

void
JsonStream::add(char c)
{
    if (is_pretty) {
        emplace(c);
        return;
    }

    if (is_prev_single_backslash) {
        emplace(c);
        is_prev_single_backslash = false;
        return;
    }

    if (c == '"') in_string = !in_string;
    if (c == '\\') is_prev_single_backslash = true;
    if (in_string || !std::isspace(c)) emplace(c);
}
