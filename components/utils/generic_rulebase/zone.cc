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

#include "generic_rulebase/zone.h"

#include <set>
#include <vector>
#include <string>

using namespace std;

static const unordered_map<string, Zone::Direction> string_to_direction = {
    { "to", Zone::Direction::To },
    { "from", Zone::Direction::From },
    { "bidirectional", Zone::Direction::Bidirectional }
};

class AdjacentZone
{
public:
    void
    load(cereal::JSONInputArchive &archive_in)
    {
        string direction_as_string;
        archive_in(cereal::make_nvp("direction", direction_as_string));
        archive_in(cereal::make_nvp("zoneId", id));
        auto maybe_direction = string_to_direction.find(direction_as_string);
        if (maybe_direction == string_to_direction.end()) {
            reportConfigurationError(
                "Illegal direction provided for adjacency. Provided direction in configuration: " +
                direction_as_string
            );
        }
        dir = maybe_direction->second;
    }

    pair<Zone::Direction, GenericConfigId> getValue() const { return make_pair(dir, id); }

private:
    Zone::Direction dir;
    GenericConfigId id;
};

class TagsValues
{
public:
    static const string req_attrs_ctx_key;

    TagsValues() {}

    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        I_Environment *env = Singleton::Consume<I_Environment>::by<Zone>();
        auto req_attrs = env->get<set<string>>(req_attrs_ctx_key);
        if (!req_attrs.ok()) return;

        for (const string &req_attr : *req_attrs) {
            try {
                string data;
                ar(cereal::make_nvp(req_attr, data));
                dbgDebug(D_RULEBASE_CONFIG)
                    << "Found value for requested attribute. Tag: "
                    << req_attr
                    << ", Value: "
                    << data;

                tags_set[req_attr].insert(data);
            } catch (const exception &e) {
                dbgDebug(D_RULEBASE_CONFIG) << "Could not find values for requested attribute. Tag: " << req_attr;
                ar.setNextName(nullptr);
            }
        }
    }

    bool
    matchValueByKey(const string &requested_key, const unordered_set<string> &possible_values) const
    {
        auto values = tags_set.find(requested_key);
        if (values == tags_set.end()) return false;

        for (const string &val : possible_values) {
            if (values->second.count(val)) return true;
        }
        return false;
    }

    void
    insert(const TagsValues &other)
    {
        for (auto &single_tags_value : other.getData()) {
            tags_set[single_tags_value.first].insert(single_tags_value.second.begin(), single_tags_value.second.end());
        }
    }

    const unordered_map<string, set<string>> & getData() const { return tags_set; }

private:
    unordered_map<string, set<string>> tags_set;
};

const string TagsValues::req_attrs_ctx_key = "requested attributes key";

void
Zone::load(cereal::JSONInputArchive &archive_in)
{
    archive_in(cereal::make_nvp("id", zone_id));
    archive_in(cereal::make_nvp("name", zone_name));
    vector<AdjacentZone> adjacency;
    try {
        archive_in(cereal::make_nvp("adjacentZones", adjacency));
    } catch (const cereal::Exception &) {
        dbgTrace(D_RULEBASE_CONFIG)
            << "List of adjacentZones does not exist for current object. Zone id: "
            << zone_id
            << ", Zone name: "
            << zone_name;

        archive_in.setNextName(nullptr);
    }

    for (const AdjacentZone &zone : adjacency) {
        adjacent_zones.push_back(zone.getValue());
    }

    archive_in(cereal::make_nvp("match", match_query));

    is_any =
        match_query.getType() == MatchQuery::MatchType::Condition &&
        match_query.getKey() == "any" &&
        match_query.getValue().count("any") > 0;

    set<string> keys = match_query.getAllKeys();
}

const string
contextKeyToString(Context::MetaDataType type)
{
    if (type == Context::MetaDataType::SubjectIpAddr || type == Context::MetaDataType::OtherIpAddr) return "ip";
    return Context::convertToString(type);
}

bool
Zone::contains(const Asset &asset)
{
    QueryRequest request;

    for (const auto &main_attr : asset.getAttrs()) {
        request.addCondition(Condition::EQUALS, contextKeyToString(main_attr.first), main_attr.second);
    }

    ScopedContext req_attrs_key;
    req_attrs_key.registerValue<set<string>>(TagsValues::req_attrs_ctx_key, match_query.getAllKeys());

    I_Intelligence_IS_V2 *intelligence = Singleton::Consume<I_Intelligence_IS_V2>::by<Zone>();
    auto query_res = intelligence->queryIntelligence<TagsValues>(request);
    if (!query_res.ok()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Failed to perform intelligence query. Error: " << query_res.getErr();
        return false;
    }

    for (const AssetReply<TagsValues> &asset : query_res.unpack()) {
        TagsValues tag_values = asset.mergeReplyData();

        if (match_query.matchAttributes(tag_values.getData())) return true;
    }
    return false;
}
