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

#include "rest.h"

using namespace std;

ostream &
RestHelper::printIndent(ostream &os, uint indent)
{
    for (uint i = 0; i < indent; i++) os << "    ";
    return os;
}

void
RestHelper::reportError(std::string const &err)
{
    throw JsonError(err);
}

Maybe<string>
ServerRest::performRestCall(istream &in)
{
    try {
        try {
            cereal::JSONInputArchive in_ar(in);
            load(in_ar);
        } catch (cereal::Exception &e) {
            throw JsonError(string("JSON parsing failed: ") + e.what());
        }
        doCall();
        stringstream out;
        {
            cereal::JSONOutputArchive out_ar(out);
            save(out_ar);
        }
        return out.str();
    } catch (const JsonError &e) {
        return genError(e.getMsg());
    }
}

void
BasicRest::performOutputingSchema(ostream &out, int level)
{
    RestHelper::printIndent(out, level) << "{\n";

    RestHelper::printIndent(out, level + 1) << "\"properties\": {";
    outputSchema(out, level + 2);
    out << "\n";
    RestHelper::printIndent(out, level + 1) << "},\n";

    RestHelper::printIndent(out, level + 1) << "\"required\": [";
    outputRequired(out, level + 2);
    out << "\n";
    RestHelper::printIndent(out, level+1) << "]\n";

    RestHelper::printIndent(out, level) << "}";
}

void
BasicRest::outputSchema(ostream &os, int level)
{
    bool first = true;
    for (auto it : schema_func) {
        if (!first) os << ',';
        os << '\n';
        it(os, level);
        first = false;
    }
}

void
BasicRest::outputRequired(ostream &os, int level)
{
    bool first = true;
    for (auto it : required) {
        if (!first) os << ',';
        os << '\n';
        RestHelper::printIndent(os, level) << "\"" << it << '"';
        first = false;
    }
}

Maybe<string>
ClientRest::genJson() const
{
    try {
        stringstream out;
        {
            cereal::JSONOutputArchive out_ar(out);
            save(out_ar);
        }
        return out.str();
    } catch (const JsonError &e) {
        return genError(e.getMsg());
    }
}

bool
ClientRest::loadJson(const string &json)
{
    try
    {
        stringstream in;
        in.str(json);
        try {
            cereal::JSONInputArchive in_ar(in);
            load(in_ar);
        } catch (cereal::Exception &e) {
            throw JsonError(string("JSON parsing failed: ") + e.what());
        }
        return true;
    }
    catch (const JsonError &j)
    {
        return false;
    }
}
