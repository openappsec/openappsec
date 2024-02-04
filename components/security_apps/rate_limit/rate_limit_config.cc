#include "rate_limit_config.h"

using namespace std;

const string RateLimitRule::default_match =
    "{\"type\":\"condition\",\"op\":\"equals\",\"key\":\"any\",\"value\":[\"any\"]}";
bool RateLimitConfig::is_active = false;

const map<RateLimitAction, string> RateLimitConfig::rate_limit_action_to_string = {
    {RateLimitAction::INACTIVE, "Inactive"},
    {RateLimitAction::ACCORDING_TO_PRACTICE, "AccordingToPractice"},
    {RateLimitAction::DETECT, "Detect"},
    {RateLimitAction::PREVENT, "Prevent"},
};


// Actions in mgmt were changed from Active/Learn to Prevent/Detect. Active/Learn are being kept here for BC.
const map<string, RateLimitAction> RateLimitConfig::rate_limit_string_to_action = {
    {"Inactive",             RateLimitAction::INACTIVE},
    {"AccordingToPractice",  RateLimitAction::ACCORDING_TO_PRACTICE},
    {"Detect",               RateLimitAction::DETECT},
    {"Learn",                RateLimitAction::DETECT},
    {"Prevent",              RateLimitAction::PREVENT},
    {"Active",               RateLimitAction::PREVENT}
};

void
RateLimitTrigger::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_RATE_LIMIT) << "Serializing single Rate Limit rule's triggers";
    try {
        ar(cereal::make_nvp("id", id));
    } catch (const cereal::Exception &e) {
        dbgWarning(D_RATE_LIMIT)
            << "Failed to load single Rate Limit JSON rule's triggers. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

void
RateLimitRule::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_RATE_LIMIT) << "Serializing single Rate Limit rule";
    try {
        string _action;
        ar(cereal::make_nvp("URI", uri));
        ar(cereal::make_nvp("scope", scope));
        ar(cereal::make_nvp("limit", limit));
        ar(cereal::make_nvp("triggers", rate_limit_triggers));
        ar(cereal::make_nvp("action", _action));
        action = RateLimitConfig::rate_limit_string_to_action.at(_action);
        ar(cereal::make_nvp("match", match));
    } catch (const cereal::Exception &e) {
        dbgWarning(D_RATE_LIMIT) << "Failed to load single Rate Limit JSON rule. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

void
RateLimitRule::prepare(const string &asset_id, int zone_id)
{
    string zone_id_s = to_string(zone_id);
    string zone;
    if (isRootLocation()) {
        zone = "root_zone_" + asset_id + "_" + zone_id_s;
    } else {
        string zone_name_suffix = uri;
        replace(zone_name_suffix.begin(), zone_name_suffix.end(), '/', '_');
        zone = "zone" + zone_name_suffix + "_" + zone_id_s;
    }

    limit_req_template_value = "zone=" + zone + " burst=" + to_string(limit) + " nodelay";

    // nginx conf will look like: limit_req_zone <sourceIdentifier> zone=<location>_<id>:10m rate=<limit>r/<scope>;
    string rate_unit = scope == "Minute" ? "r/m" : "r/s";
    limit_req_zone_template_value =
        "zone=" + zone + ":" + cache_size + " rate=" + to_string(limit) + rate_unit;

    dbgTrace(D_RATE_LIMIT)
        << "limit_req_zone nginx template value: "
        << limit_req_zone_template_value
        << ", limit_req nginx template value: "
        << limit_req_template_value;
}

bool
RateLimitRule::isRootLocation() const
{
    if (uri.empty()) {
        return false;
    }

    auto non_root = uri.find_first_not_of("/");
    if (non_root != string::npos) {
        return false;
    }
    return true;
}

bool
RateLimitRule::isMatchAny() const
{
    return
        match.getType() == MatchQuery::MatchType::Condition &&
        match.getKey() == "any" &&
        match.getValue().count("any") > 0;
}

void
RateLimitConfig::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_RATE_LIMIT) << "Serializing Rate Limit config";
    try {
        string _mode;
        ar(cereal::make_nvp("rules", rate_limit_rules));
        ar(cereal::make_nvp("mode", _mode));
        mode = rate_limit_string_to_action.at(_mode);
        prepare();
    } catch (const cereal::Exception &e) {
        dbgWarning(D_RATE_LIMIT) << "Failed to load single Rate Limit JSON config. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

RateLimitRule
RateLimitConfig::generateSiblingRateLimitRule(const RateLimitRule &rule) {
    RateLimitRule sibling_rule(rule);
    sibling_rule.appendSlash();
    sibling_rule.setExactMatch();

    return sibling_rule;
}

void
RateLimitConfig::addSiblingRateLimitRules()
{
    std::vector<RateLimitRule> siblings;
    for (auto &rule : rate_limit_rules) {
        if (rule.isExactMatch()) {
            siblings.push_back(generateSiblingRateLimitRule(rule));
            rule.setExactMatch();
        }
    }

    rate_limit_rules.insert(rate_limit_rules.end(), siblings.begin(), siblings.end());
}

void
RateLimitConfig::prepare()
{
    // Removes invalid rules
    auto last_valid_rule =
        remove_if(
            rate_limit_rules.begin(),
            rate_limit_rules.end(),
            [](const RateLimitRule &rule) { return !rule; }
        );

    rate_limit_rules.erase(last_valid_rule, rate_limit_rules.end());

    sort(rate_limit_rules.begin(), rate_limit_rules.end());

    addSiblingRateLimitRules();

    dbgTrace(D_RATE_LIMIT)
        << "Final rate-limit rules: "
        << makeSeparatedStr(rate_limit_rules, "; ");

    setIsActive(mode != RateLimitAction::INACTIVE);
}

const RateLimitRule
RateLimitConfig::findLongestMatchingRule(const string &nginx_uri) const
{
    dbgFlow(D_RATE_LIMIT) << "Trying to find a matching rat-limit rule for NGINX URI: " << nginx_uri;

    size_t longest_len = 0;
    RateLimitRule longest_matching_rule;
    for (const RateLimitRule &rule : rate_limit_rules) {
        if (rule.getRateLimitUri() == nginx_uri) {
            dbgTrace(D_RATE_LIMIT) << "Found exact rate-limit match: " << rule;
            return rule;
        }

        if (nginx_uri.size() < rule.getRateLimitUri().size()) {
            continue;
        }

        if (equal(rule.getRateLimitUri().rbegin(), rule.getRateLimitUri().rend(), nginx_uri.rbegin())) {
            if (rule.getRateLimitUri().size() > longest_len) {
                longest_matching_rule = rule;
                longest_len = rule.getRateLimitUri().size();
                dbgTrace(D_RATE_LIMIT) << "Longest matching rate-limit rule so far: " << rule;
            }
        }
    }

    dbgTrace(D_RATE_LIMIT) << "Longest matching rate-limit rule: " << longest_matching_rule;
    return longest_matching_rule;
}
