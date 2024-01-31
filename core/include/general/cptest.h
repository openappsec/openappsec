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

#if !defined(__CP_TEST_H__)
#define __CP_TEST_H__

//
// CP definitions which are useful in many unit tests
//

#include <string>
#include <vector>
#include <ostream>
#include <functional>

#include "cptest/cptest_basic.h"
#include "cptest/cptest_file.h"
#include "cptest/cptest_singleton.h"
#include "cptest/cptest_maybe.h"
#include "buffer.h"
#include "scope_exit.h"
#include "tostring.h"

std::ostream& operator<<(std::ostream &os, const Buffer &buf);

// Parse a hex string, e.g. the output of tcpdump -xx, into a vector.
std::vector<u_char> cptestParseHex(const std::string &hex_text);

// The inverse of cptest_parse_hex
// Take a vector of data, and generate hex from it output, like tcpdump.
std::string cptestGenerateHex(const std::vector<u_char> &vec, bool print_offsets);

#endif // __CP_TEST_H__
