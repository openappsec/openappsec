#include "rate_limit.h"

#include <memory>
#include <string>
#include <vector>

#include "debug.h"
#include "i_environment.h"
#include "i_mainloop.h"
#include "i_time_get.h"
#include "rate_limit_config.h"
#include "nano_attachment_common.h"
#include "http_inspection_events.h"
#include "Waf2Util.h"
#include "generic_rulebase/evaluators/asset_eval.h"
#include "generic_rulebase/parameters_config.h"
#include "WaapConfigApi.h"
#include "WaapConfigApplication.h"
#include "PatternMatcher.h"
#include "i_waapConfig.h"

#include <iostream>
#include <unordered_map>
#include <string>
#include <chrono>
#include <ctime>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "hiredis/hiredis.h"

USE_DEBUG_FLAG(D_RATE_LIMIT);

using namespace std;

enum class RateLimitVerdict { ACCEPT, DROP, DROP_AND_LOG };

class RateLimit::Impl
    :
    public Listener<HttpRequestHeaderEvent>
{
public:
    Impl() = default;
    ~Impl() = default;

    Maybe<string>
    extractUri(const string &address)
    {
        size_t protocol_pos = address.find("://");
        if (protocol_pos == string::npos) return genError("Invalid URI format: " + address);

        size_t domain_pos = address.find('/', protocol_pos + 3);
        if (domain_pos == string::npos) return string("");

        return address.substr(domain_pos);
    }

    bool
    isRuleMatchingUri(const string &rule_uri, const string &request_uri, bool should_rule_be_exact_match)
    {
        if (rule_uri.find("*") != string::npos) {
            // first condition is for 'exact match with wildcard'
            // second is for when the rule serves as a prefix
            bool wildcard_match =
                !should_rule_be_exact_match && PatternMatcherWildcard(rule_uri + "*").match(request_uri + "/");
            wildcard_match |=  PatternMatcherWildcard(rule_uri).match(request_uri);
            return wildcard_match;
        }

        return !should_rule_be_exact_match && str_starts_with(request_uri, rule_uri);
    }

    bool
    isRuleMatchingUri(const string &rule_uri, const string &request_uri, const RateLimitRule &rule)
    {
        if (rule_uri == request_uri ||
            rule_uri == request_uri + "/" ||
            rule_uri + "/" == request_uri) {
            dbgDebug(D_RATE_LIMIT)
                << "Found Exact match to request URI: "
                << request_uri
                << ", rule URI: "
                << rule_uri;
            return true;
        }

        if (rule_uri == "/") {
            dbgDebug(D_RATE_LIMIT)
                << "Matched new longest rule, request URI: "
                << request_uri
                << ", rule URI: "
                << rule_uri;
            return true;
        }

        if (isRuleMatchingUri(rule_uri, request_uri, rule.isExactMatch())) {
            dbgDebug(D_RATE_LIMIT)
                << "Matched new longest rule, request URI: "
                << request_uri
                << ", rule URI: "
                << rule_uri;
            return true;
        }

        return false;
    }

    bool
    shouldUpdateBestMatchingRule(
        const RateLimitRule &rule,
        const unordered_map<string, set<string>> &condition_map,
        int full_rule_uri_length,
        int rate_limit_longest_match,
        float current_matched_rule_limit,
        RateLimitAction current_matched_rule_verdict)
    {
        if (!rule.isMatchAny() && !rule.getRateLimitMatch().matchAttributes(condition_map)) {
            dbgTrace(D_RATE_LIMIT) << "The request does not match the rule's condition";
            return false;
        }

        RateLimitAction rule_action = calcRuleAction(rule);
        if (current_matched_rule_verdict < rule_action) {
            dbgTrace(D_RATE_LIMIT)
                << "Rule's action is more strict than already matched rule. current rule's action: "
                << RateLimitConfig::rate_limit_action_to_string.at(rule_action)
                << ", previously matched rule's action: "
                << RateLimitConfig::rate_limit_action_to_string.at(current_matched_rule_verdict);
            return true;
        }

        if (rule_action < current_matched_rule_verdict) {
            dbgTrace(D_RATE_LIMIT)
                << "Rule's action is less strict than already matched rule. current rule's action: "
                << RateLimitConfig::rate_limit_action_to_string.at(rule_action)
                << ", previously matched rule's action: "
                << RateLimitConfig::rate_limit_action_to_string.at(current_matched_rule_verdict);
            return false;
        }

        if (full_rule_uri_length < rate_limit_longest_match) {
            dbgTrace(D_RATE_LIMIT)
                << "rule is shorter than already matched rule. current rule length: "
                << full_rule_uri_length
                << ", previously longest matched rule length: "
                << rate_limit_longest_match;
            return false;
        }

        if (full_rule_uri_length == rate_limit_longest_match && current_matched_rule_limit < calcRuleLimit(rule)) {
            dbgTrace(D_RATE_LIMIT)
                << "rule limit is more permissive than already matched rule. current rule limit: "
                << limit
                << ", previously matched rule limit: "
                << current_matched_rule_limit;
            return false;
        }

        return true;
    }

    Maybe<RateLimitRule>
    findRateLimitRule(
        const string &matched_uri,
        string &asset_id,
        const unordered_map<string, set<string>> &condition_map)
    {
        WaapConfigAPI api_config;
        WaapConfigApplication application_config;
        IWaapConfig* site_config = nullptr;

        if (WaapConfigAPI::getWaapAPIConfig(api_config)) {
            site_config = &api_config;
        } else if (WaapConfigApplication::getWaapSiteConfig(application_config)) {
            site_config = &application_config;
        }

        if (site_config == nullptr) return genError("Failed to get asset configuration. Skipping rate limit check.");

        asset_id = site_config->get_AssetId();
        ScopedContext rate_limit_ctx;
        rate_limit_ctx.registerValue<GenericConfigId>(AssetMatcher::ctx_key, site_config->get_AssetId());
        auto maybe_rate_limit_config = getConfiguration<RateLimitConfig>("rulebase", "rateLimit");
        if (!maybe_rate_limit_config.ok())
            return genError("Failed to get rate limit configuration. Skipping rate limit check.");

        const auto &rate_limit_config = maybe_rate_limit_config.unpack();
        practice_action = rate_limit_config.getRateLimitMode();

        if (practice_action == RateLimitAction::INACTIVE) return genError("Rate limit mode is Inactive in policy");

        Maybe<RateLimitRule> matched_rule = genError("URI did not match any rate limit rule.");
        int rate_limit_longest_match = 0;
        float current_matched_rule_limit = 0;
        RateLimitAction current_matched_rule_verdict = RateLimitAction::INACTIVE;
        for (const auto &application_url : site_config->get_applicationUrls()) {
            dbgTrace(D_RATE_LIMIT) << "Application URL: " << application_url;

            auto maybe_uri = extractUri(application_url);
            if (!maybe_uri.ok()) {
                dbgWarning(D_RATE_LIMIT) << "Failed to extract URI from application URL: " << maybe_uri.getErr();
                continue;
            }

            string application_uri = maybe_uri.unpack();
            if (!application_uri.empty() && application_uri.back() == '/') application_uri.pop_back();

            for (const auto &rule : rate_limit_config.getRateLimitRules()) {
                string full_rule_uri = application_uri + rule.getRateLimitUri();
                transform(full_rule_uri.begin(), full_rule_uri.end(),
                    full_rule_uri.begin(), [](unsigned char c) { return std::tolower(c); });
                int full_rule_uri_length = full_rule_uri.length();

                dbgTrace(D_RATE_LIMIT)
                    << "Trying to match rule URI: "
                    << full_rule_uri
                    << " with request URI: "
                    << matched_uri;

                if (!isRuleMatchingUri(full_rule_uri, matched_uri, rule)) {
                    dbgTrace(D_RATE_LIMIT) << "No match";
                    continue;
                }

                bool should_update_rule = shouldUpdateBestMatchingRule(
                    rule,
                    condition_map,
                    full_rule_uri_length,
                    rate_limit_longest_match,
                    current_matched_rule_limit,
                    current_matched_rule_verdict);

                if (should_update_rule) {
                    matched_rule = rule;
                    rate_limit_longest_match = full_rule_uri_length;
                    current_matched_rule_verdict = calcRuleAction(rule);
                    current_matched_rule_limit = calcRuleLimit(rule);
                }
            }
        }

        return matched_rule;
    }

    void
    fetchReplicaCount()
    {
        string curl_cmd =
            base_curl_cmd + " -H \"Authorization: Bearer " + kubernetes_token + "\" "
            "https://kubernetes.default.svc.cluster.local/apis/apps/v1/namespaces/" + kubernetes_namespace +
            "/deployments/${AGENT_DEPLOYMENT_NAME} -k -s | jq .status.replicas";
        auto maybe_replicas = i_shell_cmd->getExecOutput(curl_cmd);
        if (maybe_replicas.ok()) {
            try {
                replicas = std::stoi(maybe_replicas.unpack());
                dbgTrace(D_RATE_LIMIT) << "replicas is set to " << replicas;
            } catch (const std::exception &e) {
                dbgWarning(D_RATE_LIMIT) << "error while converting replicas: " << e.what();
            }
        }
        if (replicas == 0) {
            dbgWarning(D_RATE_LIMIT) << "replicas is set to 0, setting replicas to 1";
            replicas = 1;
        }
    }

    EventVerdict
    respond(const HttpRequestHeaderEvent &event) override
    {
        if (!event.isLastHeader()) return INSPECT;

        auto env = Singleton::Consume<I_Environment>::by<RateLimit>();
        auto uri_ctx = env->get<string>(HttpTransactionData::uri_ctx);
        if (!uri_ctx.ok()) {
            dbgWarning(D_RATE_LIMIT) << "Unable to get URL from context, Not enforcing rate limit";
            return ACCEPT;
        }

        auto uri = uri_ctx.unpack();
        transform(uri.begin(), uri.end(), uri.begin(), [](unsigned char c) { return tolower(c); });

        auto maybe_source_identifier = env->get<string>(HttpTransactionData::source_identifier);
        if (!maybe_source_identifier.ok()) {
            dbgWarning(D_RATE_LIMIT) << "Unable to get source identifier from context, not enforcing rate limit";
            return ACCEPT;
        }

        auto &source_identifier = maybe_source_identifier.unpack();
        dbgDebug(D_RATE_LIMIT) << "source identifier value: " << source_identifier;

        auto maybe_source_ip = env->get<IPAddr>(HttpTransactionData::client_ip_ctx);
        set<string> ip_set;
        string source_ip = "";
        if (maybe_source_ip.ok()) {
            source_ip = ipAddrToStr(maybe_source_ip.unpack());

            if (getProfileAgentSettingWithDefault<bool>(false, "agent.rateLimit.ignoreSourceIP")) {
                dbgDebug(D_RATE_LIMIT) << "Rate limit ignoring source ip: " << source_ip;
            } else {
                ip_set.insert(source_ip);
            }
        }

        auto maybe_xff = env->get<string>(HttpTransactionData::xff_vals_ctx);
        if (!maybe_xff.ok()) {
            dbgTrace(D_RATE_LIMIT) << "Rate limit failed to get xff vals from env";
        } else {
            auto ips = split(maybe_xff.unpack(), ',');
            ip_set.insert(ips.begin(), ips.end());
        }

        EnumArray<I_GeoLocation::GeoLocationField, string> geo_location_data;
        set<string> country_codes;
        set<string> country_names;
        for (const string& source : ip_set) {
            Maybe<IPAddr> maybe_source_ip = IPAddr::createIPAddr(source);
            if (!maybe_source_ip.ok()){
                dbgWarning(D_RATE_LIMIT)
                    << "Rate limit failed to create ip address from source: "
                    << source
                    << ", Error: "
                    << maybe_source_ip.getErr();
                continue;
            }
            auto asset_location =
                Singleton::Consume<I_GeoLocation>::by<RateLimit>()->lookupLocation(maybe_source_ip.unpack());
            if (!asset_location.ok()) {
                dbgDebug(D_RATE_LIMIT)
                    << "Rate limit lookup location failed for source: "
                    << source_ip
                    << ", Error: "
                    << asset_location.getErr();
                continue;
            }
            geo_location_data = asset_location.unpack();
            auto code = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE];
            auto name =  geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_NAME];
            country_codes.insert(code);
            country_names.insert(name);
            dbgTrace(D_RATE_LIMIT)
                << "Rate limit found "
                << "country code: "
                << code
                << ", country name: "
                << name
                << ", source ip address: "
                << source;
        }


        unordered_map<string, set<string>> condition_map = createConditionMap(
            uri,
            source_ip,
            source_identifier,
            country_codes,
            country_names
        );
        if (shouldApplyException(condition_map)) {
            dbgDebug(D_RATE_LIMIT) << "found accept exception, not enforcing rate limit on this URI: " << uri;
            return ACCEPT;
        }

        string asset_id;
        auto maybe_rule = findRateLimitRule(uri, asset_id, condition_map);
        if (!maybe_rule.ok()) {
            dbgDebug(D_RATE_LIMIT) << "Not Enforcing Rate Limit: " << maybe_rule.getErr();
            return ACCEPT;
        }

        const auto &rule = maybe_rule.unpack();
        if (rule.getRateLimitAction() == RateLimitAction::INACTIVE) {
            dbgDebug(D_RATE_LIMIT) << "Rule's action is Inactive, rate limit will not be enforced";
            return ACCEPT;
        }

        burst = static_cast<float>(rule.getRateLimit()) / replicas;
        limit = static_cast<float>(calcRuleLimit(rule)) / replicas;

        dbgTrace(D_RATE_LIMIT)
            << "found rate limit rule with: "
            << rule.getRateLimit()
            << " per "
            << (rule.getRateLimitScope() == "Minute" ? 60 : 1)
            << " seconds";

        string unique_key = asset_id + ":" + source_identifier + ":" + rule.getRateLimitUri();
        if (unique_key.back() == '/') unique_key.pop_back();

        auto verdict = decide(unique_key);
        if (verdict == RateLimitVerdict::ACCEPT) {
            dbgTrace(D_RATE_LIMIT) << "Received ACCEPT verdict.";
            return ACCEPT;
        }

        if (verdict == RateLimitVerdict::DROP_AND_LOG) sendLog(uri, source_identifier, source_ip, rule);

        if (calcRuleAction(rule) == RateLimitAction::PREVENT) {
            dbgTrace(D_RATE_LIMIT) << "Received DROP verdict, this request will be blocked by rate limit";

            EventVerdict verdict = DROP;
            ScopedContext rate_limit_ctx;
            rate_limit_ctx.registerValue<GenericConfigId>(AssetMatcher::ctx_key, asset_id);
            auto maybe_rate_limit_config = getConfiguration<RateLimitConfig>("rulebase", "rateLimit");
            if (maybe_rate_limit_config.ok()) {
                const string &web_user_response_id = maybe_rate_limit_config.unpack().getWebUserResponse();
                if (!web_user_response_id.empty()) {
                    verdict.setWebUserResponseByPractice(web_user_response_id);
                    dbgTrace(D_RATE_LIMIT) << "Set web user response: " << web_user_response_id;
                }
            }
            return verdict;
        }

        dbgTrace(D_RATE_LIMIT) << "Received DROP in detect mode, will not block.";
        return ACCEPT;
    }

    RateLimitAction
    calcRuleAction(const RateLimitRule &rule)
    {
        if (rule.getRateLimitAction() == RateLimitAction::ACCORDING_TO_PRACTICE) return practice_action;

        return rule.getRateLimitAction();
    }

    float
    calcRuleLimit(const RateLimitRule &rule)
    {
        return static_cast<float>(rule.getRateLimit()) / (rule.getRateLimitScope() == "Minute" ? 60 : 1);
    }

    string
    getListenerName() const override
    {
        return "rate limit";
    }

    RateLimitVerdict
    decide(const string &key) {
        if (redis == nullptr) {
            dbgDebug(D_RATE_LIMIT)
                << "there is no connection to the redis at the moment, unable to enforce rate limit";
            reconnectRedis();
            return RateLimitVerdict::ACCEPT;
        }

        redisReply* reply = static_cast<redisReply*>(redisCommand(redis, "EVALSHA %s 1 %s %f %d",
        rate_limit_lua_script_hash.c_str(), key.c_str(), limit, burst));

        if (reply == NULL || redis->err) {
            dbgDebug(D_RATE_LIMIT)
                << "Error executing Redis command: No reply received, unable to enforce rate limit";
            reconnectRedis();
            return RateLimitVerdict::ACCEPT;
        }

        // redis's lua script returned true - accept
        if (reply->type == REDIS_REPLY_INTEGER) {
            freeReplyObject(reply);
            return RateLimitVerdict::ACCEPT;
        }

        // redis's lua script returned false - drop, no need to log
        if (reply->type == REDIS_REPLY_NIL) {
            freeReplyObject(reply);
            return RateLimitVerdict::DROP;
        }

        // redis's lua script returned string - drop and send log
        const char* log_str = "BLOCK AND LOG";
        if (reply->type == REDIS_REPLY_STRING && strncmp(reply->str, log_str, strlen(log_str)) == 0) {
            freeReplyObject(reply);
            return RateLimitVerdict::DROP_AND_LOG;
        }

        dbgDebug(D_RATE_LIMIT)
            << "Got unexected reply from redis. reply type: "
            << reply->type
            << ". not enforcing rate limit for this request.";
        freeReplyObject(reply);
        return RateLimitVerdict::ACCEPT;
    }

    void
    sendLog(const string &uri, const string &source_identifier, const string &source_ip, const RateLimitRule &rule)
    {
        set<string> rate_limit_triggers_set;
        for (const auto &trigger : rule.getRateLimitTriggers()) {
            rate_limit_triggers_set.insert(trigger.getTriggerId());
        }

        ScopedContext ctx;
        ctx.registerValue<set<GenericConfigId>>(TriggerMatcher::ctx_key, rate_limit_triggers_set);
        auto log_trigger = getConfigurationWithDefault(LogTriggerConf(), "rulebase", "log");

        if (!log_trigger.isPreventLogActive(LogTriggerConf::SecurityType::AccessControl)) {
            dbgTrace(D_RATE_LIMIT) << "Not sending rate-limit log as it is not required";
            return;
        }

        auto maybe_rule_by_ctx = getConfigurationWithCache<BasicRuleConfig>("rulebase", "rulesConfig");
        if (!maybe_rule_by_ctx.ok()) {
            dbgWarning(D_RATE_LIMIT)
                << "rule was not found by the given context. Reason: "
                << maybe_rule_by_ctx.getErr();
            return;
        }

        string event_name = "Rate limit";

        LogGen log = log_trigger(
            event_name,
            LogTriggerConf::SecurityType::AccessControl,
            ReportIS::Severity::HIGH,
            ReportIS::Priority::HIGH,
            true,
            LogField("practiceType", "Rate Limit"),
            ReportIS::Tags::RATE_LIMIT
        );

        const auto &rule_by_ctx = maybe_rule_by_ctx.unpack();

        log
            << LogField("assetId", rule_by_ctx.getAssetId())
            << LogField("assetName", rule_by_ctx.getAssetName())
            << LogField("ruleId", rule_by_ctx.getRuleId())
            << LogField("ruleName", rule_by_ctx.getRuleName())
            << LogField("httpUriPath", uri)
            << LogField("httpSourceId", source_identifier)
            << LogField("securityAction", (calcRuleAction(rule) == RateLimitAction::PREVENT ? "Prevent" : "Detect"))
            << LogField("waapIncidentType", "Rate Limit");

        auto env = Singleton::Consume<I_Environment>::by<RateLimit>();
        auto http_method = env->get<string>(HttpTransactionData::method_ctx);
        if (http_method.ok()) log << LogField("httpMethod", http_method.unpack());

        auto http_host = env->get<string>(HttpTransactionData::host_name_ctx);
        if (http_host.ok()) log << LogField("httpHostName", http_host.unpack());

        if (!source_ip.empty()) log << LogField("sourceIP", source_ip);

        auto proxy_ip = env->get<string>(HttpTransactionData::proxy_ip_ctx);
        if (proxy_ip.ok() && !source_ip.empty() && source_ip != proxy_ip.unpack()) {
            log << LogField("proxyIP", static_cast<string>(proxy_ip.unpack()));
        }
    }

    bool
    shouldApplyException(const unordered_map<string, set<string>> &exceptions_dict)
    {
        dbgTrace(D_RATE_LIMIT) << "matching exceptions";

        auto behaviors = Singleton::Consume<I_GenericRulebase>::by<RateLimit>()->getBehavior(exceptions_dict);
        for (auto const &behavior : behaviors) {
            if (behavior == action_accept) {
                dbgTrace(D_RATE_LIMIT) << "matched exceptions for current request, should accept";
                return true;
            }
        }

        dbgTrace(D_RATE_LIMIT) << "No accept exceptions found for this request";
        return false;
    }

    unordered_map<string, set<string>>
    createConditionMap(
        const string &uri,
        const string &source_ip,
        const string &source_identifier,
        const set<string> &country_codes,
        const set<string> &country_names
    )
    {
        unordered_map<string, set<string>> condition_map;
        if (!source_ip.empty()) condition_map["sourceIP"].insert(source_ip);
        if (!country_codes.empty()) condition_map["countryCode"].insert(country_codes.begin(), country_codes.end());
        if (!country_names.empty()) condition_map["countryName"].insert(country_names.begin(), country_names.end());
        condition_map["sourceIdentifier"].insert(source_identifier);
        condition_map["url"].insert(uri);

        return condition_map;
    }

    string
    ipAddrToStr(const IPAddr& ip_address) const
    {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_address), str, INET_ADDRSTRLEN);
        return string(str);
    }

    Maybe<void>
    connectRedis()
    {
        disconnectRedis();

        const string redis_ip = getConfigurationWithDefault<string>("127.0.0.1", "connection", "Redis IP");
        int redis_port = getConfigurationWithDefault<int>(6379, "connection", "Redis Port");

        timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = getConfigurationWithDefault<int>(30000, "connection", "Redis Timeout");

        redisContext* context = redisConnectWithTimeout(redis_ip.c_str(), redis_port, timeout);
        if (context != nullptr && context->err) {
            dbgDebug(D_RATE_LIMIT)
                << "Error connecting to Redis: "
                << context->errstr;
            redisFree(context);
            return genError("");
        }

        if (context == nullptr) return genError("");

        redis = context;
        static string luaScript = R"(
            local key = KEYS[1]
            local rateLimit = tonumber(ARGV[1])
            local burstLimit = tonumber(ARGV[2])
            local currentTimeSeconds = tonumber(redis.call('time')[1])
            local lastRequestTimeSeconds = tonumber(redis.call('get', key .. ':lastRequestTime') or "0")
            local elapsedTimeSeconds = currentTimeSeconds - lastRequestTimeSeconds
            local tokens = tonumber(redis.call('get', key .. ':tokens') or burstLimit)
            local was_blocked = tonumber(redis.call('get', key .. ':block') or "0")

            tokens = math.min(tokens + (elapsedTimeSeconds * rateLimit), burstLimit)

            if tokens >= 1 then
                tokens = tokens - 1
                redis.call('set', key .. ':tokens', tokens)
                redis.call('set', key .. ':lastRequestTime', currentTimeSeconds)
                redis.call('expire', key .. ':tokens', 60)
                redis.call('expire', key .. ':lastRequestTime', 60)
                return true
            elseif was_blocked == 1 then
                redis.call('set', key .. ':block', 1)
                redis.call('expire', key .. ':block', 60)
                return false
            else
                redis.call('set', key .. ':block', 1)
                redis.call('expire', key .. ':block', 60)
                return "BLOCK AND LOG"
            end
        )";

        // Load the Lua script in Redis and retrieve its SHA1 hash
        redisReply* loadReply =
            static_cast<redisReply*>(redisCommand(redis, "SCRIPT LOAD %s", luaScript.c_str()));
        if (loadReply != nullptr && loadReply->type == REDIS_REPLY_STRING) {
            rate_limit_lua_script_hash = loadReply->str;
            freeReplyObject(loadReply);
        }

        return Maybe<void>();
    }

    void
    reconnectRedis()
    {
        dbgFlow(D_RATE_LIMIT) << "Trying to reconnect to redis after failure to invoke a redis command";
        static bool is_reconnecting = false;
        if (!is_reconnecting) {
            is_reconnecting = true;
            Singleton::Consume<I_MainLoop>::by<RateLimit>()->addOneTimeRoutine(
                I_MainLoop::RoutineType::System,
                [this] ()
                {
                    connectRedis();
                    is_reconnecting = false;
                },
                "Reconnect redis",
                false
            );
        }
    }

    void
    handleNewPolicy()
    {
        if (RateLimitConfig::isActive() && !redis) {
            connectRedis();
            registerListener();
            return;
        }

        if (!RateLimitConfig::isActive()) {
            disconnectRedis();
            unregisterListener();
        }
    }

    void
    disconnectRedis()
    {
        if (redis) {
            redisFree(redis);
            redis = nullptr;
        }
    }

    void
    init()
    {
        Singleton::Consume<I_MainLoop>::by<RateLimit>()->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this] ()
            {
                handleNewPolicy();
                registerConfigLoadCb([this]() { handleNewPolicy(); });
            },
            "Initialize rate limit component",
            false
        );

        i_shell_cmd = Singleton::Consume<I_ShellCmd>::by<RateLimit>();
        i_env_details = Singleton::Consume<I_EnvDetails>::by<RateLimit>();
        env_type = i_env_details->getEnvType();
        const char *nexus_env = getenv("KUBERNETES_METADATA");
        if (nexus_env == nullptr) return;
        if (env_type == EnvType::K8S && string(nexus_env) == "true") {
            kubernetes_token = i_env_details->getToken();
            kubernetes_namespace = i_env_details->getNameSpace();
            fetchReplicaCount();
            Singleton::Consume<I_MainLoop>::by<RateLimit>()->addRecurringRoutine(
                I_MainLoop::RoutineType::Offline,
                chrono::seconds(120),
                [this]() { fetchReplicaCount(); },
                "Fetch current replica count from the Kubernetes cluster"
            );
        }
    }

    void
    fini()
    {
        disconnectRedis();
    }

    I_ShellCmd *i_shell_cmd = nullptr;
    I_EnvDetails* i_env_details = nullptr;

private:
    static constexpr auto DROP = ServiceVerdict::TRAFFIC_VERDICT_DROP;
    static constexpr auto ACCEPT = ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
    static constexpr auto INSPECT = ServiceVerdict::TRAFFIC_VERDICT_INSPECT;

    RateLimitAction practice_action;
    string rate_limit_lua_script_hash;
    int burst;
    float limit;
    redisContext* redis = nullptr;
    int replicas = 1;
    EnvType env_type;
    string kubernetes_namespace = "";
    string kubernetes_token = "";
#if defined(gaia)
    const string base_curl_cmd = "curl_cli";
#elif defined(alpine)
    const string base_curl_cmd = "LD_LIBRARY_PATH=/usr/lib/:/usr/lib/cpnano curl";
#else
    const string base_curl_cmd = "curl";
#endif
};

RateLimit::RateLimit() : Component("RateLimit"), pimpl(make_unique<Impl>()) {}

RateLimit::~RateLimit() = default;

void
RateLimit::preload()
{
    registerExpectedConfigurationWithCache<WaapConfigApplication>("assetId", "WAAP", "WebApplicationSecurity");
    registerExpectedConfigurationWithCache<WaapConfigAPI>("assetId", "WAAP", "WebAPISecurity");
    registerExpectedConfigFile("waap", Config::ConfigFileType::Policy);
    registerExpectedConfiguration<RateLimitConfig>("rulebase", "rateLimit");
    registerExpectedConfigFile("accessControlV2", Config::ConfigFileType::Policy);
    registerConfigPrepareCb([]() { RateLimitConfig::resetIsActive(); });
}

void
RateLimit::init() { pimpl->init(); }

void
RateLimit::fini() { pimpl->fini(); }
