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

#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <iterator>
#include <istream>
#include <ostream>

#include "base64.h"

using namespace std;

const string Base64::base64_base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string
Base64::encodeBase64(const string &input)
{
    string out;
    int val = 0, val_base = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        val_base += 8;
        while (val_base >= 0) {
            out.push_back(base64_base[(val >> val_base) & 0x3F]);
            val_base -= 6;
        }
    }
    // -6 indicates the number of bits to take from each character
    // (6 bits is enough to present a range of 0 to 63)
    if (val_base > -6) out.push_back(base64_base[((val << 8) >> (val_base + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');

    return out;
}

string
Base64::decodeBase64(const string &input)
{
    vector<int> mapper(256, -1);
    for (int i = 0; i < 64; i++) mapper[base64_base[i]] = i;

    string out;
    int val = 0, val_base = -8;
    for (unsigned char c : input) {
        if (mapper[c] == -1) break;
        val = (val << 6) + mapper[c];
        val_base += 6;
        if (val_base >= 0) {
            out.push_back(char((val >> val_base) & 0xFF));
            val_base -= 8;
        }
    }

    return out;
}
