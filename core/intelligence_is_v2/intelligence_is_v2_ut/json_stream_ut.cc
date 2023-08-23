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

#include "cptest.h"
#include "cereal/archives/json.hpp"
#include "boost/algorithm/string.hpp"
#include "boost/format.hpp"

#include <sstream>

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_INTELLIGENCE);

string
addSlashesToSpecialChars(const string &input)
{
    string output;
    for(auto c : input)
    {
        switch (c)
        {
        case '\n':
            output += "\\n";
            break;
        case '\t':
            output += "\\t";
            break;
        case '\"':
        case '\\':
            output += '\\';
            //no break
        default:
            output += c;
            break;
        }
    }

    return output;
}

void
testJsonStream(const string &key, const string &value, bool is_pretty)
{
    stringstream str_stream;
    JsonStream json_stream(&str_stream, is_pretty);
    {
        cereal::JSONOutputArchive out_ar(json_stream);
        out_ar.setNextName("regular_num");
        out_ar.writeName();
        out_ar.saveValue(15.34);
        out_ar.setNextName(key.c_str());
        out_ar.writeName();
        out_ar.saveValue(value.c_str());
    }

    string expected_key = addSlashesToSpecialChars(key);
    string expected_value = addSlashesToSpecialChars(value);

    const string JSON_STRING_WITH_SPACES = "{\n    \"regular_num\": 15.34,\n    \"%s\": \"%s\"\n}";
    const string JSON_STRING_WITHOUT_SPACES = "{\"regular_num\":15.34,\"%s\":\"%s\"}";
    boost::format frmt(is_pretty ? JSON_STRING_WITH_SPACES : JSON_STRING_WITHOUT_SPACES);
    frmt = frmt % expected_key;
    frmt = frmt % expected_value;

    string expected = frmt.str();
    string actual = str_stream.str();
    EXPECT_EQ(actual, expected);
}

TEST(JsonStreamTest, prettyOneWord)
{
    testJsonStream("regular_key", "regular_value", true);
}

TEST(JsonStreamTest, unprettyOneWord)
{
    testJsonStream("regular_key", "regular_value", false);
}

TEST(JsonStreamTest, prettyTwoWords)
{
    testJsonStream("spaced key", "spaced value", true);
}

TEST(JsonStreamTest, unprettyTwoWords)
{
    testJsonStream("spaced key", "spaced value", false);
}

TEST(JsonStreamTest, prettyWithEnterTab)
{
    testJsonStream("entered\nkey", "tabbed\tvalue", true);
}

TEST(JsonStreamTest, unprettyWithEnterTab)
{
    testJsonStream("entered\nkey", "tabbed\tvalue", false);
}

TEST(JsonStreamTest, prettyWithQout)
{
    testJsonStream("qout \" key\"", "qout \" value\"", true);
}

TEST(JsonStreamTest, unprettyWithQout)
{
    testJsonStream("qout \" key\"", "qout \" value\"", false);
}

TEST(JsonStreamTest, prettyWithSlashQout)
{
    testJsonStream("qout \\\" key\\\"", "qout \\\" value\\\"", true);
}

TEST(JsonStreamTest, unprettyWithSlashQout)
{
    testJsonStream("qout \\\" key\\\"", "qout \\\" value\\\"", false);
}
