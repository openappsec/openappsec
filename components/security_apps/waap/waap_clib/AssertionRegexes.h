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

#ifndef __ASSERTION_REGEXES_H__
#define __ASSERTION_REGEXES_H__

#include <boost/regex.hpp>

namespace Waap {
namespace AssertionRegexes {

// Static const boost regexes used in processAssertions() function
// These regexes detect various assertion patterns in regex strings
// The patterns are in a separate file to avoid this codestyle checker issue:
// "error T009: comma should be followed by whitespace"
static const boost::regex reStartNonWordBehind(R"(\(\?<!\\w\))");  // (?<!\w)
static const boost::regex reEndNonWordAhead(R"(\(\?!\\w\))");      // (?!\w)
static const boost::regex reEndNonWordSpecial(R"(\(\?=\[\^\\w\?<>:=\]\|\$\))"); // (?=[^\w?<>:=]|$)
static const boost::regex rePathTraversalStart(R"(\(\?<!\[\\\.\,:\]\))"); // (?<![\.,:])
static const boost::regex rePathTraversalEnd(R"(\(\?!\[\\\.\,:\]\))");    // (?![\.,:])

} // namespace AssertionRegexes
} // namespace Waap

#endif // __ASSERTION_REGEXES_H__
