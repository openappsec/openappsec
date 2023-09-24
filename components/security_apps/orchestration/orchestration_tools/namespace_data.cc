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

#include "namespace_data.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

template <typename T>
void
parseNameSpaceJSONKey(
    const string &key_name,
    T &value,
    cereal::JSONInputArchive &archive_in,
    const T &default_value = T())
{
    try {
        archive_in(cereal::make_nvp(key_name, value));
    } catch (const cereal::Exception &e) {
        archive_in.setNextName(nullptr);
        value = default_value;
        dbgDebug(D_ORCHESTRATOR)
            << "Could not parse the required key. Key: "
            << key_name
            << ", Error: "
            << e.what();
    }
}

class NamespaceMetadata
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        dbgFlow(D_ORCHESTRATOR);
        parseNameSpaceJSONKey<string>("name", name, archive_in);
        parseNameSpaceJSONKey<string>("uid", uid, archive_in);
    }

    const string &
    getName() const
    {
        return name;
    }

    const string &
    getUID() const
    {
        return uid;
    }

private:
    string name;
    string uid;
};

class SingleNamespaceData
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        parseNameSpaceJSONKey<NamespaceMetadata>("metadata", metadata, archive_in);
    }

    const NamespaceMetadata &
    getMetadata() const
    {
        return metadata;
    }

private:
    NamespaceMetadata metadata;
};

bool
NamespaceData::loadJson(const string &json)
{
    dbgFlow(D_ORCHESTRATOR);
    string modified_json = json;
    modified_json.pop_back();
    stringstream in;
    in.str(modified_json);
    try {
        cereal::JSONInputArchive in_ar(in);
        vector<SingleNamespaceData> items;
        in_ar(cereal::make_nvp("items", items));
        for (const SingleNamespaceData &single_ns_data : items) {
            ns_name_to_uid[single_ns_data.getMetadata().getName()] = single_ns_data.getMetadata().getUID();
        }
    } catch (cereal::Exception &e) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to load namespace data JSON. Error: " << e.what();
        return false;
    }
    return true;
}

Maybe<string>
NamespaceData::getNamespaceUidByName(const string &name)
{
    if (ns_name_to_uid.find(name) == ns_name_to_uid.end()) {
        return genError("Namespace doesn't exist. Name: " + name);
    }
    return ns_name_to_uid.at(name);
}
