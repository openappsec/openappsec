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

#ifndef __JSON_STREAM_H__
#define __JSON_STREAM_H__

#include <ostream>

class JsonStream : public std::streambuf, public std::ostream
{
public:
    JsonStream(std::ostream *os, bool is_pretty);

private:
    int overflow(int c) override;
    void emplace(char c);
    void add(char c);

    std::ostream *os;
    bool is_prev_single_backslash = false;
    bool is_pretty;
    bool in_string = false;
};

#endif // __JSON_STREAM_H__
