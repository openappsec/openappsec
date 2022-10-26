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

#include "picojson.h"

using namespace std;

int
main(int argc, char **argv)
{
    if (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "--help")) {
        cout << "Use standard input to send the JSON string. "
                "Prettified JSON will be sent to the standard output" << endl;
        return 1;
    }
    picojson::value json;
    cin >> json;
    string maybe_err = picojson::get_last_error();
    if (!maybe_err.empty()) {
        cerr << maybe_err << endl;
        return 1;
    }
    cout << json.serialize(true, false) << endl;
    return 0;
}
