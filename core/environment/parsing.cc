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

#include "environment_evaluator.h"

#include <sstream>
#include <algorithm>

#include "enum_range.h"

using namespace std;
using namespace EnvironmentHelper;

USE_DEBUG_FLAG(D_ENVIRONMENT);

void
reportWrongNumberOfParams(const string &eval_name, uint no_params, uint min, uint max)
{
    ostringstream os;
    os <<
        "Wrong number of parameters for '" <<
        eval_name <<
        "'. Got " <<
        no_params <<
        " parameters instead of expected ";
    if (min == max) {
        os << min;
    } else if (max == static_cast<uint>(-1)) {
        os << "more than " << min;
    } else {
        os << "between " << min << " and " << max;
    }
    dbgTrace(D_ENVIRONMENT) << os.str();
    EvaluatorParseError err(os.str());
    throw err;
}

void
reportWrongParamType(const string &eval_name, const string &param, const string &reason)
{
    ostringstream os;
    os << "Parameter '" << param << "' for '" << eval_name << "' is of the wrong type because: " << reason;
    dbgTrace(D_ENVIRONMENT) << os.str();

    EvaluatorParseError err(os.str());
    throw err;
}

void
reportUnknownEvaluatorType(const string &eval_name)
{
    ostringstream os;
    os << "Evaluator '" << eval_name << "' doesn't exist for the required type";
    dbgTrace(D_ENVIRONMENT) << os.str();

    EvaluatorParseError err(os.str());
    throw err;
}

static string
trim(const string &str)
{
    auto first = str.find_first_not_of(' ');
    if (first == string::npos) return "";
    auto last = str.find_last_not_of(' ');
    return str.substr(first, (last-first+1));
}

static vector<string>
breakToParams(const string &list)
{
    vector<string> res;

    uint brackets = 0;
    uint start = 0;
    for (uint iter : makeRange(list.size())) {
        switch (list[iter]) {
            case ',': {
                if (brackets == 0) {
                    res.push_back(trim(list.substr(start, iter-start)));
                    start = iter + 1;
                }
                break;
            }
            case '(': {
                brackets++;
                break;
            }
            case ')': {
                brackets--;
                break;
            }
            default: {
                break;
            }
        }
    }

    // Add the last section
    if (start < list.size()) res.push_back(trim(list.substr(start, list.size()-start)));

    dbgTrace(D_ENVIRONMENT) << "Param vector size: " << res.size();
    return res;
}

pair<string, vector<string>>
EnvironmentHelper::breakEvaluatorString(const string &str)
{
    auto trimmed = trim(str);

    auto open_bracket = trimmed.find('(');
    if (open_bracket == string::npos) {
        dbgTrace(D_ENVIRONMENT) << "Could not find the opening bracket in the string";
        throw EvaluatorParseError("Could not find the opening bracket in the string");
    }
    auto close_bracket = trimmed.size() - 1;
    if (trimmed[close_bracket] != ')') {
        dbgTrace(D_ENVIRONMENT) << "Could not find the closing bracket in the string";
        throw EvaluatorParseError("Could not find the closing bracket in the string");
    }

    auto command = trimmed.substr(0, open_bracket);
    auto params = trimmed.substr(open_bracket + 1, close_bracket - open_bracket - 1);

    dbgTrace(D_ENVIRONMENT) << "Breaking evaluator string passed successfully";
    return make_pair(trim(command), breakToParams(trim(params)));
}
