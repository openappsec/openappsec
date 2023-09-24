#ifndef __RATE_LIMIT_CONFIG_H__
#define __RATE_LIMIT_CONFIG_H__

#include <string>
#include <vector>
#include <algorithm>
#include <cereal/archives/json.hpp>

#include "debug.h"
#include "generic_rulebase/rulebase_config.h"
#include "generic_rulebase/triggers_config.h"
#include "generic_rulebase/evaluators/trigger_eval.h"

USE_DEBUG_FLAG(D_REVERSE_PROXY);

class RateLimitTrigger
{
public:
    void
    load(cereal::JSONInputArchive &ar);

    const std::string & getTriggerId() const { return id; }

private:
    std::string id;
};

class RateLimitRule
{
public:
    void load(cereal::JSONInputArchive &ar);
    void prepare(const std::string &asset_id, int zone_id);

    operator bool() const
    {
        if (uri.empty()) {
            dbgTrace(D_REVERSE_PROXY) << "Recived empty URI in rate-limit rule";
            return false;
        }

        if (uri.at(0) != '/') {
            dbgWarning(D_REVERSE_PROXY)
                << "Recived invalid rate-limit URI in rate-limit rule: "
                << uri
                << " rate-limit URI must start with /";
            return false;
        }

        if (limit <= 0) {
            dbgWarning(D_REVERSE_PROXY)
                << "Recived invalid rate-limit limit in rate-limit rule: "
                << limit
                << " rate-limit rule limit must be positive";
            return false;
        }

        return true;
    }

    friend std::ostream &
    operator<<(std::ostream &os, const RateLimitRule &rule)
    {
        os << "Uri: " << rule.uri << ", Rate scope: " << rule.scope << ", Limit: " << rule.limit;

        return os;
    }

    int getRateLimit() const { return limit; }
    const std::string & getRateLimitZone() const { return limit_req_zone_template_value; }
    const std::string & getRateLimitReq() const { return limit_req_template_value; }
    const std::string & getRateLimitUri() const { return uri; }
    const std::string & getRateLimitScope() const { return scope; }
    const LogTriggerConf & getRateLimitTrigger() const { return trigger; }
    const std::vector<RateLimitTrigger> & getRateLimitTriggers() const { return rate_limit_triggers; }

    bool isRootLocation() const;

    bool operator==(const RateLimitRule &rhs) { return uri == rhs.uri; }
    bool operator<(const RateLimitRule &rhs) { return uri < rhs.uri; }
    bool isExactMatch() const { return exact_match || (!uri.empty() && uri.back() != '/'); }
    void setExactMatch() { exact_match = true; }
    void appendSlash() { uri += '/'; }

private:
    std::string uri;
    std::string scope;
    std::string limit_req_template_value;
    std::string limit_req_zone_template_value;
    std::string cache_size = "5m";
    std::vector<RateLimitTrigger> rate_limit_triggers;
    LogTriggerConf trigger;
    int limit;
    bool exact_match = false;
};

class RateLimitConfig
{
public:
    void load(cereal::JSONInputArchive &ar);
    void addSiblingRateLimitRule(RateLimitRule &rule);
    void prepare();

    const std::vector<RateLimitRule> & getRateLimitRules() const { return rate_limit_rules; }
    const std::string & getRateLimitMode() const { return mode; }

    const LogTriggerConf
    getRateLimitTrigger(const std::string &nginx_uri) const
    {
        const RateLimitRule rule = findLongestMatchingRule(nginx_uri);

        std::set<std::string> rate_limit_triggers_set;
        for (const RateLimitTrigger &rate_limit_trigger : rule.getRateLimitTriggers()) {
            dbgTrace(D_REVERSE_PROXY)
                << "Adding trigger ID: "
                << rate_limit_trigger.getTriggerId()
                << " of rule URI: "
                << rule.getRateLimitUri()
                << " to the context set";
            rate_limit_triggers_set.insert(rate_limit_trigger.getTriggerId());
        }

        ScopedContext ctx;
        ctx.registerValue<std::set<GenericConfigId>>(TriggerMatcher::ctx_key, rate_limit_triggers_set);
        return getConfigurationWithDefault(LogTriggerConf(), "rulebase", "log");
    }

    static void setIsActive(bool _is_active) { is_active |= _is_active; }

    static void resetIsActive() { is_active = false; }

    static bool isActive() { return is_active; }

private:
    const RateLimitRule
    findLongestMatchingRule(const std::string &nginx_uri) const;

    static bool is_active;
    std::string mode;
    std::vector<RateLimitRule> rate_limit_rules;
};

#endif // __RATE_LIMIT_CONFIG_H__
