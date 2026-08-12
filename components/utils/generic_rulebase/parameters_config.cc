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

// Forward declaration - defined below, used by getBehaviorForNonKVPairs()
static bool checkMatchQueryForKVPair(const MatchQuery &query);

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

    const auto &mkeys = match.getAllKeys();
    all_referenced_keys.insert(mkeys.begin(), mkeys.end());
    for (const auto &mbp : match_queries) {
        const auto &k = mbp.match.getAllKeys();
        all_referenced_keys.insert(k.begin(), k.end());
    }

    if (all_referenced_keys.count("countryCode") || all_referenced_keys.count("countryName")) {
        is_geo_location_exception_being_loaded = true;
    }

    is_containing_kv_pair = checkKVPair();

    // Precompute KV/non-KV split of match_queries to avoid per-request filtering.
    for (size_t i = 0; i < match_queries.size(); ++i) {
        if (checkMatchQueryForKVPair(match_queries[i].match)) {
            kv_match_query_indices.push_back(i);
        } else {
            non_kv_match_query_indices.push_back(i);
        }
    }
}

set<ParameterBehavior>
ParameterException::getBehavior(
    const unordered_map<string, set<string>> &key_value_pairs,
    set<string> &matched_override_keywords,
    bool skip_irrelevant_key) const
{
    set<ParameterBehavior> matched_behaviors;

    matched_override_keywords.clear();
    dbgTrace(D_RULEBASE_CONFIG) << "Matching exception";
    for (const MatchBehaviorPair &match_behavior_pair: match_queries) {
        MatchQuery::MatchResult match_res = match_behavior_pair.match.getMatch(key_value_pairs, skip_irrelevant_key);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG)
                << "Successfully matched an exception from a list of matches, behavior: "
                << match_behavior_pair.behavior.getId();
            // When matching indicators with action=ignore, we expect no behavior override.
            // Instead, a matched keywords list should be returned which will be later removed from score calculation
            if (match_res.matched_keywords->size() > 0 && match_behavior_pair.behavior == action_ignore) {
                matched_override_keywords.insert(match_res.matched_keywords->begin(),
                        match_res.matched_keywords->end());
                dbgTrace(D_RULEBASE_CONFIG) << "Got action ignore, found " <<
                    matched_override_keywords.size() << "keywords";
            } else {
                matched_behaviors.insert(match_behavior_pair.behavior);
            }
        }
    }

    if (match_queries.empty()) {
        MatchQuery::MatchResult match_res = match.getMatch(key_value_pairs, skip_irrelevant_key);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG) << "Successfully matched an exception.";
            // When matching indicators with action=ignore, we expect no behavior override.
            // Instead, a matched keywords list should be returned which will be later removed from score calculation
            if (match_res.matched_keywords->size() > 0 && behavior == action_ignore) {
                matched_override_keywords.insert(match_res.matched_keywords->begin(),
                        match_res.matched_keywords->end());
                dbgTrace(D_RULEBASE_CONFIG) << "Got action ignore, found " <<
                    matched_override_keywords.size() << "keywords";
            } else {
                matched_behaviors.insert(behavior);
            }
        }
    }

    return matched_behaviors;
}

set<ParameterBehavior>
ParameterException::getBehavior(
    const unordered_map<string, set<string>> &key_value_pairs,
    bool skip_irrelevant_key) const
{
    set<string> keywords; // placeholder only, this function will be used where there's no need for ignored keywords
    return getBehavior(key_value_pairs, keywords, skip_irrelevant_key);
}

set<ParameterBehavior>
ParameterException::getBehaviorForNonKVPairs(
    const unordered_map<string, set<string>> &key_value_pairs) const
{
    set<ParameterBehavior> matched_behaviors;

    dbgTrace(D_RULEBASE_CONFIG) << "Matching non-KV pair exceptions only";
    for (size_t idx : non_kv_match_query_indices) {
        const MatchBehaviorPair &mbp = match_queries[idx];
        MatchQuery::MatchResult match_res = mbp.match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG)
                << "Successfully matched a non-KV exception, behavior: "
                << mbp.behavior.getId();
            matched_behaviors.insert(mbp.behavior);
        }
    }

    if (match_queries.empty() && !is_containing_kv_pair) {
        MatchQuery::MatchResult match_res = match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG) << "Successfully matched a non-KV exception (single match).";
            matched_behaviors.insert(behavior);
        }
    }

    return matched_behaviors;
}

namespace {

struct TagUsage { bool positive = false; bool negated = false; };

void
collectTagUsage(const MatchQuery &query, const string &key, TagUsage &usage)
{
    if (query.getType() == MatchQuery::MatchType::Condition) {
        if (query.getKey() == key) {
            MatchQuery::Conditions cond = query.getConditionType();
            if (cond == MatchQuery::Conditions::NotEquals || cond == MatchQuery::Conditions::NotIn) {
                usage.negated = true;
            } else {
                usage.positive = true;
            }
        }
        return;
    }
    for (const MatchQuery &child : query.getItems()) collectTagUsage(child, key, usage);
}

bool
matchesAnyRequestPair(
    const MatchQuery &query,
    const unordered_map<string, set<string>> &base_dict,
    const vector<pair<string, string>> &kv_pairs,
    const string &name_tag,
    const string &value_tag)
{
    if (kv_pairs.empty()) return false;

    TagUsage name_usage, value_usage;
    collectTagUsage(query, name_tag, name_usage);
    collectTagUsage(query, value_tag, value_usage);

    if ((name_usage.positive && name_usage.negated) ||
        (value_usage.positive && value_usage.negated)) {
        dbgTrace(D_RULEBASE_CONFIG) << "pair tag used both positively and negatively - no match";
        return false;
    }

    unordered_map<string, set<string>> dict = base_dict;
    if (name_usage.negated) {
        set<string> all_names;
        for (const auto &p : kv_pairs) all_names.insert(p.first);
        dict[name_tag] = all_names;
    }
    if (value_usage.negated) {
        set<string> all_values;
        for (const auto &p : kv_pairs) all_values.insert(p.second);
        dict[value_tag] = all_values;
    }
    if (name_usage.negated && value_usage.negated) return query.matchAttributes(dict);

    for (const auto &p : kv_pairs) {
        if (!name_usage.negated) dict[name_tag] = {p.first};
        if (!value_usage.negated) dict[value_tag] = {p.second};
        if (query.matchAttributes(dict)) return true;
    }
    return false;
}

struct PairTagCounts { unsigned hN = 0, hV = 0, pN = 0, pV = 0; };

PairTagCounts
countPairTags(const MatchQuery &q)
{
    PairTagCounts c;
    if (q.getType() == MatchQuery::MatchType::Condition) {
        const string &k = q.getKey();
        if (k == "headerName") c.hN = 1;
        else if (k == "headerValue") c.hV = 1;
        else if (k == "paramName") c.pN = 1;
        else if (k == "paramValue") c.pV = 1;
        return c;
    }
    if (q.getType() == MatchQuery::MatchType::Operator &&
        q.getOperatorType() == MatchQuery::Operators::And) {
        for (const MatchQuery &child : q.getItems()) {
            PairTagCounts cc = countPairTags(child);
            c.hN += cc.hN; c.hV += cc.hV; c.pN += cc.pN; c.pV += cc.pV;
        }
    }
    return c;
}

struct KVCtx {
    const unordered_map<string, set<string>> &base_dict;
    const vector<pair<string, string>> &header_pairs;
    const vector<pair<string, string>> &param_pairs;
};

bool
matchesCorrelatedFamilies(const MatchQuery &query, const KVCtx &ctx)
{
    if (ctx.header_pairs.empty() || ctx.param_pairs.empty()) return false;

    const unordered_set<string> &keys = query.getAllKeys();
    bool full_hdr = keys.count("headerName") && keys.count("headerValue");
    bool full_par = keys.count("paramName") && keys.count("paramValue");

    unordered_map<string, set<string>> dict = ctx.base_dict;
    if (!full_hdr) {
        set<string> names, values;
        for (const auto &h : ctx.header_pairs) { names.insert(h.first); values.insert(h.second); }
        dict["headerName"] = move(names);
        dict["headerValue"] = move(values);
    }
    if (!full_par) {
        set<string> names, values;
        for (const auto &p : ctx.param_pairs) { names.insert(p.first); values.insert(p.second); }
        dict["paramName"] = move(names);
        dict["paramValue"] = move(values);
    }

    if (!full_hdr && !full_par) {
        dbgTrace(D_RULEBASE_CONFIG) << "neither family is fully bound - matching request-wide";
        return query.matchAttributes(dict);
    }

    if (!full_par) {
        dbgTrace(D_RULEBASE_CONFIG) << "correlating headers, params unbound";
        for (const auto &h : ctx.header_pairs) {
            dict["headerName"] = {h.first};
            dict["headerValue"] = {h.second};
            if (query.matchAttributes(dict)) return true;
        }
        return false;
    }
    if (!full_hdr) {
        dbgTrace(D_RULEBASE_CONFIG) << "correlating params, headers unbound";
        for (const auto &p : ctx.param_pairs) {
            dict["paramName"] = {p.first};
            dict["paramValue"] = {p.second};
            if (query.matchAttributes(dict)) return true;
        }
        return false;
    }

    dbgTrace(D_RULEBASE_CONFIG) << "correlating both header and param families";
    for (const auto &h : ctx.header_pairs) {
        dict["headerName"] = {h.first};
        dict["headerValue"] = {h.second};
        for (const auto &p : ctx.param_pairs) {
            dict["paramName"] = {p.first};
            dict["paramValue"] = {p.second};
            if (query.matchAttributes(dict)) return true;
        }
    }
    return false;
}

bool
matchKVAware(const MatchQuery &query, const KVCtx &ctx)
{
    const unordered_set<string> &keys = query.getAllKeys();
    bool has_hdr = keys.count("headerName") || keys.count("headerValue");
    bool has_par = keys.count("paramName")  || keys.count("paramValue");

    if (!has_hdr && !has_par) {
        return query.matchAttributes(ctx.base_dict);
    }

    if (query.getType() == MatchQuery::MatchType::Operator &&
        query.getOperatorType() == MatchQuery::Operators::And) {
        bool any_full_pair_child = false;
        for (const MatchQuery &child : query.getItems()) {
            const unordered_set<string> &ck = child.getAllKeys();
            bool ck_full_hdr = ck.count("headerName") && ck.count("headerValue");
            bool ck_full_par = ck.count("paramName")  && ck.count("paramValue");
            if (ck_full_hdr || ck_full_par) { any_full_pair_child = true; break; }
        }
        PairTagCounts tc = countPairTags(query);
        bool mixed = has_hdr && has_par;

        if (any_full_pair_child || tc.hN > 1 || tc.hV > 1 || tc.pN > 1 || tc.pV > 1) {
            dbgTrace(D_RULEBASE_CONFIG) << "AND has a full pair child or a repeated tag - decomposing fully";
            for (const MatchQuery &child : query.getItems()) {
                if (!matchKVAware(child, ctx)) return false;
            }
            return true;
        }
        if (mixed) {
            dbgTrace(D_RULEBASE_CONFIG) << "AND mixes header and param tags - correlating by family";
            return matchesCorrelatedFamilies(query, ctx);
        }
    }

    if (query.getType() == MatchQuery::MatchType::Operator &&
        query.getOperatorType() == MatchQuery::Operators::Or) {
        for (const MatchQuery &child : query.getItems()) {
            if (matchKVAware(child, ctx)) return true;
        }
        return false;
    }

    if (has_hdr && !has_par) {
        dbgTrace(D_RULEBASE_CONFIG) << "header-only condition - matching against any header pair";
        return matchesAnyRequestPair(query, ctx.base_dict, ctx.header_pairs,
            "headerName", "headerValue");
    }
    if (has_par && !has_hdr) {
        dbgTrace(D_RULEBASE_CONFIG) << "param-only condition - matching against any param pair";
        return matchesAnyRequestPair(query, ctx.base_dict, ctx.param_pairs,
            "paramName", "paramValue");
    }
    return false;
}

}

set<ParameterBehavior>
ParameterException::getBehaviorForKVPairs(
    const unordered_map<string, set<string>> &base_dict,
    const vector<pair<string, string>> &header_pairs,
    const vector<pair<string, string>> &param_pairs) const
{
    set<ParameterBehavior> matched_behaviors;
    KVCtx ctx{base_dict, header_pairs, param_pairs};
    for (size_t idx : kv_match_query_indices) {
        const MatchBehaviorPair &mbp = match_queries[idx];
        if (matchKVAware(mbp.match, ctx)) {
            matched_behaviors.insert(mbp.behavior);
        }
    }
    if (match_queries.empty() && is_containing_kv_pair) {
        if (matchKVAware(match, ctx)) {
            matched_behaviors.insert(behavior);
        }
    }
    return matched_behaviors;
}

set<ParameterBehavior>
ParameterException::getBehaviorForKVList(
    const unordered_map<string, set<string>> &base_dict,
    const vector<pair<string, string>> &kv_pairs,
    const string &name_tag,
    const string &) const
{
    static const vector<pair<string, string>> empty;
    vector<pair<string, string>> lowered_pairs;
    if (name_tag == "headerName") {
        lowered_pairs.reserve(kv_pairs.size());
        for (const auto &p : kv_pairs) {
            string n = p.first;
            string v = p.second;
            transform(n.begin(), n.end(), n.begin(), ::tolower);
            transform(v.begin(), v.end(), v.begin(), ::tolower);
            lowered_pairs.emplace_back(move(n), move(v));
        }
    }
    const auto &header_pairs = (name_tag == "headerName") ? lowered_pairs : empty;
    const auto &param_pairs  = (name_tag == "paramName")  ? kv_pairs : empty;

    return getBehaviorForKVPairs(base_dict, header_pairs, param_pairs);
}

set<ParameterBehavior>
ParameterException::getBehaviorForKVPairsOnly(
    const unordered_map<string, set<string>> &key_value_pairs) const
{
    set<ParameterBehavior> matched_behaviors;

    dbgTrace(D_RULEBASE_CONFIG) << "Matching KV pair exceptions only";
    for (size_t idx : kv_match_query_indices) {
        const MatchBehaviorPair &mbp = match_queries[idx];
        MatchQuery::MatchResult match_res = mbp.match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG)
                << "Successfully matched a KV exception, behavior: "
                << mbp.behavior.getId();
            matched_behaviors.insert(mbp.behavior);
        }
    }

    if (match_queries.empty() && is_containing_kv_pair) {
        MatchQuery::MatchResult match_res = match.getMatch(key_value_pairs);
        if (match_res.is_match) {
            dbgTrace(D_RULEBASE_CONFIG) << "Successfully matched a KV exception (single match).";
            matched_behaviors.insert(behavior);
        }
    }

    return matched_behaviors;
}

static bool
checkMatchQueryForKVPair(const MatchQuery &query)
{
    if (query.getType() == MatchQuery::MatchType::Condition) {
        return false;
    }

    if (query.getType() == MatchQuery::MatchType::Operator) {
        if (query.getOperatorType() == MatchQuery::Operators::And) {
            // Collect ALL keys from the entire AND subtree (recursive),
            // not just direct Condition children. This handles nested binary-tree
            // structures generated by the management server (INXT-52398).
            const std::unordered_set<std::string> &all_keys = query.getAllKeys();

            if (all_keys.count("paramName") && all_keys.count("paramValue")) {
                return true;
            }

            if (all_keys.count("headerName") && all_keys.count("headerValue")) {
                return true;
            }
        }

        // Recurse into sub-operators (handles OR nodes containing KV pairs)
        for (const MatchQuery &item : query.getItems()) {
            if (item.getType() == MatchQuery::MatchType::Operator) {
                if (checkMatchQueryForKVPair(item)) {
                    return true;
                }
            }
        }
    }

    return false;
}

bool
ParameterException::checkKVPair() const
{
    if (checkMatchQueryForKVPair(match)) {
        return true;
    }

    for (const MatchBehaviorPair &match_behavior_pair : match_queries) {
        if (checkMatchQueryForKVPair(match_behavior_pair.match)) {
            return true;
        }
    }

    return false;
}
