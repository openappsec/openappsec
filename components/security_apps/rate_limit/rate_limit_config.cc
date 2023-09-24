#include "rate_limit_config.h"

bool RateLimitConfig::is_active = false;

void
RateLimitTrigger::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_REVERSE_PROXY) << "Serializing single Rate Limit rule's triggers";
    try {
        ar(cereal::make_nvp("id", id));
    } catch (const cereal::Exception &e) {
        dbgWarning(D_REVERSE_PROXY)
            << "Failed to load single Rate Limit JSON rule's triggers. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

void
RateLimitRule::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_REVERSE_PROXY) << "Serializing single Rate Limit rule";
    try {
        ar(cereal::make_nvp("URI", uri));
        ar(cereal::make_nvp("scope", scope));
        ar(cereal::make_nvp("limit", limit));
        ar(cereal::make_nvp("triggers", rate_limit_triggers));
    } catch (const cereal::Exception &e) {
        dbgWarning(D_REVERSE_PROXY) << "Failed to load single Rate Limit JSON rule. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

void
RateLimitRule::prepare(const std::string &asset_id, int zone_id)
{
    std::string zone_id_s = std::to_string(zone_id);
    std::string zone;
    if (isRootLocation()) {
        zone = "root_zone_" + asset_id + "_" + zone_id_s;
    } else {
        std::string zone_name_suffix = uri;
        std::replace(zone_name_suffix.begin(), zone_name_suffix.end(), '/', '_');
        zone = "zone" + zone_name_suffix + "_" + zone_id_s;
    }

    limit_req_template_value = "zone=" + zone + " burst=" + std::to_string(limit) + " nodelay";

    // nginx conf will look like: limit_req_zone <sourceIdentifier> zone=<location>_<id>:10m rate=<limit>r/<scope>;
    std::string rate_unit = scope == "Minute" ? "r/m" : "r/s";
    limit_req_zone_template_value =
        "zone=" + zone + ":" + cache_size + " rate=" + std::to_string(limit) + rate_unit;

    dbgTrace(D_REVERSE_PROXY)
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
    if (non_root != std::string::npos) {
        return false;
    }
    return true;
}

void
RateLimitConfig::load(cereal::JSONInputArchive &ar)
{
    dbgTrace(D_REVERSE_PROXY) << "Serializing Rate Limit config";
    try {
        ar(cereal::make_nvp("rules", rate_limit_rules));
        ar(cereal::make_nvp("mode", mode));
        prepare();
    } catch (const cereal::Exception &e) {
        dbgWarning(D_REVERSE_PROXY) << "Failed to load single Rate Limit JSON config. Error: " << e.what();
        ar.setNextName(nullptr);
    }
}

void
RateLimitConfig::addSiblingRateLimitRule(RateLimitRule &rule) {
    rule.setExactMatch();
    RateLimitRule sibling_rule(rule);
    sibling_rule.appendSlash();
    sibling_rule.setExactMatch();
    rate_limit_rules.push_back(sibling_rule);
}

void
RateLimitConfig::prepare()
{
    // Removes invalid rules
    auto last_valid_rule =
        std::remove_if(
            rate_limit_rules.begin(),
            rate_limit_rules.end(),
            [](const RateLimitRule &rule) { return !rule; }
        );

    rate_limit_rules.erase(last_valid_rule, rate_limit_rules.end());

    // Removes duplicates
    sort(rate_limit_rules.begin(), rate_limit_rules.end());
    rate_limit_rules.erase(std::unique(rate_limit_rules.begin(), rate_limit_rules.end()), rate_limit_rules.end());

    std::for_each(
        rate_limit_rules.begin(),
        rate_limit_rules.end(),
        [this](RateLimitRule &rule) { if (rule.isExactMatch()) { addSiblingRateLimitRule(rule); } }
    );

    dbgTrace(D_REVERSE_PROXY)
        << "Final rate-limit rules: "
        << makeSeparatedStr(rate_limit_rules, "; ")
        << "; Mode: "
        << mode;

    setIsActive(mode != "Inactive");
}

const RateLimitRule
RateLimitConfig::findLongestMatchingRule(const std::string &nginx_uri) const
{
    dbgFlow(D_REVERSE_PROXY) << "Trying to find a matching rat-limit rule for NGINX URI: " << nginx_uri;

    size_t longest_len = 0;
    RateLimitRule longest_matching_rule;
    for (const RateLimitRule &rule : rate_limit_rules) {
        if (rule.getRateLimitUri() == nginx_uri) {
            dbgTrace(D_REVERSE_PROXY) << "Found exact rate-limit match: " << rule;
            return rule;
        }

        if (nginx_uri.size() < rule.getRateLimitUri().size()) {
            continue;
        }

        if (std::equal(rule.getRateLimitUri().rbegin(), rule.getRateLimitUri().rend(), nginx_uri.rbegin())) {
            if (rule.getRateLimitUri().size() > longest_len) {
                longest_matching_rule = rule;
                longest_len = rule.getRateLimitUri().size();
                dbgTrace(D_REVERSE_PROXY) << "Longest matching rate-limit rule so far: " << rule;
            }
        }
    }

    dbgTrace(D_REVERSE_PROXY) << "Longest matching rate-limit rule: " << longest_matching_rule;
    return longest_matching_rule;
}
