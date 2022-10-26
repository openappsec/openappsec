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

#include "config.h"

using namespace cereal;
using namespace std;

template<>
void
Config::ConfigLoader<bool>::readValue(JSONInputArchive &ar)
{
    ar(make_nvp("value", value));
}

template<>
void
Config::ConfigLoader<int>::readValue(JSONInputArchive &ar)
{
    ar(make_nvp("value", value));
}

template<>
void
Config::ConfigLoader<uint>::readValue(JSONInputArchive &ar)
{
    ar(make_nvp("value", value));
}

template<>
void
Config::ConfigLoader<string>::readValue(JSONInputArchive &ar)
{
    ar(make_nvp("value", value));
}

template<>
bool
Config::loadProfileSetting<bool>(const string &raw_value)
{
    if (raw_value == "true") {
        return true;
    } else if (raw_value == "false") {
        return false;
    } else {
        throw Exception("Illegal Value");
    }
}

template<>
int
Config::loadProfileSetting<int>(const string &raw_value)
{
    return stoi(raw_value);
}

template<>
uint
Config::loadProfileSetting<uint>(const string &raw_value)
{
    return stoul(raw_value);
}

template<>
string
Config::loadProfileSetting<string>(const string &raw_value)
{
    return raw_value;
}
