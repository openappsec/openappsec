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

#include "generic_rulebase/parameters_config.h"

USE_DEBUG_FLAG(D_RULEBASE_CONFIG);

using namespace std;

bool ParameterException::is_geo_location_exception_exists(false);
bool ParameterException::is_geo_location_exception_being_loaded(false);

void
ParameterOverrides::load(cereal::JSONInputArchive &archive_in)
{
    parseJSONKey<vector<ParsedBehavior>>("parsedBehavior", parsed_behaviors, archive_in);
}

void
ParameterTrustedSources::load(cereal::JSONInputArchive &archive_in)
{
    parseJSONKey<uint>("numOfSources", num_of_sources, archive_in);
    parseJSONKey<vector<SourcesIdentifier>>("sourcesIdentifiers", sources_identidiers, archive_in);
}

void
ParameterBehavior::load(cereal::JSONInputArchive &archive_in)
{
    string key_string;
    string val_string;
    parseJSONKey<string>("id", id, archive_in);
    parseJSONKey<string>("key", key_string, archive_in);
    parseJSONKey<string>("value", val_string, archive_in);
    if (string_to_behavior_key.find(key_string) == string_to_behavior_key.end()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Unsupported behavior key: " << key_string;
        return;
    }
    key = string_to_behavior_key.at(key_string);

    if (string_to_behavior_val.find(val_string) == string_to_behavior_val.end()) {
        dbgWarning(D_RULEBASE_CONFIG) << "Unsupported behavior value: " << val_string;
        return;
    }
    value = string_to_behavior_val.at(val_string);
}

void
ParameterAntiBot::load(cereal::JSONInputArchive &archive_in)
{
    parseJSONKey<vector<string>>("injected", injected, archive_in);
    parseJSONKey<vector<string>>("validated", validated, archive_in);
}

void
ParameterOAS::load(cereal::JSONInputArchive &archive_in)
{
    parseJSONKey<string>("value", value, archive_in);
}

void
ParameterException::MatchBehaviorPair::load(cereal::JSONInputArchive &archive_in)
{
    parseJSONKey<MatchQuery>("match", match, archive_in);
    parseJSONKey<ParameterBehavior>("behavior", behavior, archive_in);
}

void
ParameterException::load(cereal::JSONInputArchive &archive_in)
{
    try {
        archive_in(
            cereal::make_nvp("match", match),
            cereal::make_nvp("behavior", behavior)
        );
    } catch (...) {
        parseJSONKey<vector<MatchBehaviorPair>>("exceptions", match_queries, archive_in);
    }

    function<bool(const MatchQuery &)> isGeoLocationExists =
        [&](const MatchQuery &query)
        {
            if (query.getKey() == "countryCode" || query.getKey() == "countryName") {
                is_geo_location_exception_being_loaded = true;
                return true;
            }

            for (const MatchQuery &query_item : query.getItems()) {
                if (isGeoLocationExists(query_item)) return true;
            }

            return false;
        };

    if (isGeoLocationExists(match)) return;
    for (const MatchBehaviorPair &match_query : match_queries) {
        if (isGeoLocationExists(match_query.match)) return;
    }
}

set<ParameterBehavior>
ParameterException::getBehavior(
        const unordered_map<string, set<string>> &key_value_pairs,
        set<string> &matched_override_keywords) const
{
    set<ParameterBehavior> matched_behaviors;

    matched_override_keywords.clear();
    dbgTrace(D_RULEBASE_CONFIG) << "Matching exception";
    for (const MatchBehaviorPair &match_behavior_pair: match_queries) {
        MatchQuery::MatchResult match_res = match_behavior_pair.match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG) << "Successfully matched an exception from a list of matches.";
            // When matching indicators with action=ignore, we expect no behavior override.
            // Instead, a matched keywords list should be returned which will be later removed from score calculation
            if (match_res.matched_keywords->size() > 0 && match_behavior_pair.behavior == action_ignore) {
                matched_override_keywords.insert(match_res.matched_keywords->begin(),
                        match_res.matched_keywords->end());
            } else {
                matched_behaviors.insert(match_behavior_pair.behavior);
            }
        }
    }

    if (match_queries.empty()) {
        MatchQuery::MatchResult match_res = match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG) << "Successfully matched an exception.";
            // When matching indicators with action=ignore, we expect no behavior override.
            // Instead, a matched keywords list should be returned which will be later removed from score calculation
            if (match_res.matched_keywords->size() > 0 && behavior == action_ignore) {
                matched_override_keywords.insert(match_res.matched_keywords->begin(),
                        match_res.matched_keywords->end());
            } else {
                matched_behaviors.insert(behavior);
            }
        }
    }

    return matched_behaviors;
}

set<ParameterBehavior>
ParameterException::getBehavior(const unordered_map<string, set<string>> &key_value_pairs) const
{
    set<string> keywords;
    return getBehavior(key_value_pairs, keywords);
}
