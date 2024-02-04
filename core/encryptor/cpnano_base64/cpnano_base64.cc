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
#include <iterator>
#include <istream>
#include <ostream>

#include "base64.h"

using namespace std;

// LCOV_EXCL_START Reason: main func tested in systemtest
int
main(int argc, char **argv)
{
    if (argc < 2) {
        cerr << "No arguments were provided" << endl;
        exit(1);
    }

    // don't skip the whitespace while reading
    cin >> noskipws;
    // use stream iterators to copy the stream to a string
    istream_iterator<char> it(cin);
    istream_iterator<char> end;
    string input(it, end);

    if (string(argv[1]) == "-d" || string(argv[1]) == "--decode") {
        cout << Base64::decodeBase64(input) << endl;
    } else if(string(argv[1]) == "-e" || string(argv[1]) == "--encode") {
        cout << Base64::encodeBase64(input) << endl;
    } else {
        cerr << "Argument provided is illegal (options are -d|-e). Provided arg: " << string(argv[1]) << endl;
        exit(2);
    }

    exit(0);
}
// LCOV_EXCL_STOP
