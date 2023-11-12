#include "layer_7_access_control.h"

#include <string>
#include <boost/algorithm/string/case_conv.hpp>
#include <unordered_set>

#include "config.h"
#include "cache.h"
#include "http_inspection_events.h"
#include "nginx_attachment_common.h"
#include "intelligence_comp_v2.h"
#include "intelligence_is_v2/query_request_v2.h"
#include "log_generator.h"

USE_DEBUG_FLAG(D_L7_ACCESS_CONTROL);

using namespace std;
using namespace Intelligence_IS_V2;

static const string crowdsec_enabled_value = "true";
static const string crowdsec_asset_type = "data-cloud-ip-crowdSec";

class IntelligenceIpReputation
{
public:
    template <class Archive>
    void
    load(Archive &ar)
    {
        try {
            vector<string> ipv4_addresses;
            ar(cereal::make_nvp("type", type));
            ar(cereal::make_nvp("scenario", scenario));
            ar(cereal::make_nvp("origin", origin));
            ar(cereal::make_nvp("crowdsecId", crowdsec_event_id));
            ar(cereal::make_nvp("ipv4Addresses", ipv4_addresses));
            if (!ipv4_addresses.empty()) ipv4_address = ipv4_addresses.front();
        } catch (const cereal::Exception &e) {
            dbgWarning(D_L7_ACCESS_CONTROL) << "Failed to load IP reputation data JSON. Error: " << e.what();
        }
    }

    Maybe<LogField>
    getType() const
    {
        if (type.empty()) return genError("Empty type");
        return LogField("externalVendorRecommendedAction", type);
    }

    Maybe<LogField>
    getScenario() const
    {
        if (scenario.empty()) return genError("Empty scenario");
        return LogField("externalVendorRecommendationOriginDetails", scenario);
    }

    Maybe<LogField>
    getOrigin() const
    {
        if (origin.empty()) return genError("Empty origin");
        return LogField("externalVendorRecommendationOrigin", origin);
    }

    Maybe<LogField>
    getIpv4Address() const
    {
        if (ipv4_address.empty()) return genError("Empty ipv4 address");
        return LogField("externalVendorRecommendedAffectedScope", ipv4_address);
    }

    Maybe<LogField>
    getCrowdsecEventId() const
    {
        if (!crowdsec_event_id) return genError("Empty ID");
        return LogField("externalVendorRecommendationId", to_string(crowdsec_event_id));
    }

    bool isMalicious() const { return type == "ban"; }

    void
    print(std::ostream &out) const
    {
        out
            << "Crowdsec event ID: "
            << crowdsec_event_id
            << ", IPV4 address: "
            << ipv4_address
            << ", type: "
            << type
            << ", origin: "
            << origin
            << ", scenario: "
            << scenario;
    }

private:
    string type;
    string scenario;
    string origin;
    string ipv4_address;
    unsigned int crowdsec_event_id;
};

class Layer7AccessControl::Impl : public Listener<HttpRequestHeaderEvent>, Listener<WaitTransactionEvent>
{
public:
    void init();
    void fini();

    string getListenerName() const override { return "Layer-7 Access Control app"; }

    EventVerdict
    respond(const HttpRequestHeaderEvent &event) override
    {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Handling a new layer-7 access control event: " << event;

        if (!isAppEnabled()) {
            dbgTrace(D_L7_ACCESS_CONTROL) << "Returning Accept verdict as the Layer-7 Access Control app is disabled";
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
        }

        if (!event.isLastHeader()) {
            dbgTrace(D_L7_ACCESS_CONTROL) << "Returning Inspect verdict";
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
        }

        return handleEvent();
    }

    EventVerdict
    respond(const WaitTransactionEvent &) override
    {
        dbgFlow(D_L7_ACCESS_CONTROL) << "Handling wait verdict";

        return handleEvent();
    }

private:
    void queryIntelligence();
    void scheduleIntelligenceQuery(const string &ip);
    void processIntelligenceResponse(const string &ip, const vector<AssetReply<IntelligenceIpReputation>> &response);
    Maybe<IntelligenceIpReputation> getIpReputation(const string &ip);
    EventVerdict generateLog(const string &source_ip, const IntelligenceIpReputation &ip_reputation) const;
    EventVerdict queryIpReputation(const string &source_ip);
    EventVerdict handleEvent();

    bool isAppEnabled() const;
    bool isPrevent() const;

    Maybe<LogField, Context::Error> genLogField(const string &log_key, const string &env_key) const;
    Maybe<LogField, Context::Error> genLogIPField(const string &log_key, const string &env_key) const;

    bool is_intelligence_routine_running = false;
    I_Environment *i_env = nullptr;
    I_Intelligence_IS_V2 *i_intelligence = nullptr;
    I_MainLoop *i_mainloop = nullptr;
    TemporaryCache<string, IntelligenceIpReputation> ip_reputation_cache;
    unordered_set<string> pending_ips;
};

bool
Layer7AccessControl::Impl::isAppEnabled() const
{
    bool enabled = getenv("CROWDSEC_ENABLED") ? string(getenv("CROWDSEC_ENABLED")) == crowdsec_enabled_value : false;
    return getProfileAgentSettingWithDefault<bool>(enabled, "layer7AccessControl.crowdsec.enabled");
}

bool
Layer7AccessControl::Impl::isPrevent() const
{
    string security_mode_env = getenv("CROWDSEC_MODE") ? getenv("CROWDSEC_MODE") : "prevent";
    string mode = getProfileAgentSettingWithDefault(security_mode_env,  "layer7AccessControl.securityMode");

    dbgTrace(D_L7_ACCESS_CONTROL) << "Selected security mode: " << mode;

    return mode == "prevent";
}

void
Layer7AccessControl::Impl::scheduleIntelligenceQuery(const string &ip)
{
    dbgFlow(D_L7_ACCESS_CONTROL) << "Scheduling intelligence query about reputation of IP: " << ip;

    pending_ips.emplace(ip);

    if (!is_intelligence_routine_running) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Starting intelligence routine";
        is_intelligence_routine_running = true;
        i_mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [&] () { queryIntelligence(); },
            "Check IP reputation"
        );
    }
}

Maybe<IntelligenceIpReputation>
Layer7AccessControl::Impl::getIpReputation(const string &ip)
{
    dbgFlow(D_L7_ACCESS_CONTROL) << "Getting reputation of IP " << ip;
    if (ip_reputation_cache.doesKeyExists(ip)) return ip_reputation_cache.getEntry(ip);

    dbgTrace(D_L7_ACCESS_CONTROL) << ip << " reputation was not found in cache";

    return genError("Intelligence needed");
}

EventVerdict
Layer7AccessControl::Impl::queryIpReputation(const string &source_ip)
{
    auto ip_reputation = getIpReputation(source_ip);
    if (!ip_reputation.ok()) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Scheduling Intelligence query  - returning Wait verdict";
        scheduleIntelligenceQuery(source_ip);
        return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_WAIT;
    }

    if (!ip_reputation.unpack().isMalicious()) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Accepting IP: " << source_ip;
        ip_reputation_cache.deleteEntry(source_ip);
        return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
    }

    return generateLog(source_ip, ip_reputation.unpack());
}

EventVerdict
Layer7AccessControl::Impl::handleEvent()
{
    auto source_identifier = i_env->get<string>(HttpTransactionData::source_identifier);
    if (source_identifier.ok() && IPAddr::createIPAddr(source_identifier.unpack()).ok()) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Found a valid source identifier value: " << source_identifier.unpack();
        return queryIpReputation(source_identifier.unpack());
    }

    auto orig_source_ip = i_env->get<IPAddr>(HttpTransactionData::client_ip_ctx);
    if (orig_source_ip.ok()) {
        stringstream ss_client_ip;
        ss_client_ip << orig_source_ip.unpack();
        return queryIpReputation(ss_client_ip.str());
    }

    dbgWarning(D_L7_ACCESS_CONTROL) << "Could not extract the Client IP address from context";
    return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
}

void
Layer7AccessControl::Impl::processIntelligenceResponse(
    const string &ip,
    const vector<AssetReply<IntelligenceIpReputation>> &response)
{
    if (response.empty()) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Intelligence reputation response collection is empty. IP is clean.";
        ip_reputation_cache.emplaceEntry(ip, IntelligenceIpReputation());
        return;
    }

    for (const auto &intelligence_reply : response) {
        if (intelligence_reply.getAssetType() == crowdsec_asset_type && !intelligence_reply.getData().empty()) {
            dbgTrace(D_L7_ACCESS_CONTROL) << intelligence_reply.getData().front();
            ip_reputation_cache.emplaceEntry(ip, intelligence_reply.getData().front());
            return;
        }
    }

    dbgTrace(D_L7_ACCESS_CONTROL) << "Could not find a matching intelligence asset type for IP: " << ip;
    ip_reputation_cache.emplaceEntry(ip, IntelligenceIpReputation());
}

void
Layer7AccessControl::Impl::queryIntelligence()
{
    dbgFlow(D_L7_ACCESS_CONTROL) << "Started IP reputation intelligence routine";

    while (!pending_ips.empty()) {
        i_mainloop->yield();

        auto ip = *(pending_ips.begin());
        pending_ips.erase(pending_ips.begin());

        if (ip_reputation_cache.doesKeyExists(ip)) continue;

        dbgTrace(D_L7_ACCESS_CONTROL) << "Querying intelligence about reputation of IP: " << ip;

        QueryRequest request = QueryRequest(
            Condition::EQUALS,
            "ipv4Addresses",
            ip,
            true,
            AttributeKeyType::REGULAR
        );

        auto response = i_intelligence->queryIntelligence<IntelligenceIpReputation>(request);

        if (!response.ok()) {
            dbgWarning(D_L7_ACCESS_CONTROL)
                << "Failed to query intelligence about reputation of IP: "
                << ip
                << ", error: "
                << response.getErr();
            ip_reputation_cache.emplaceEntry(ip, IntelligenceIpReputation());
            continue;
        }

        processIntelligenceResponse(ip, response.unpack());
    }

    is_intelligence_routine_running = false;
}

EventVerdict
Layer7AccessControl::Impl::generateLog(const string &source_ip, const IntelligenceIpReputation &ip_reputation) const
{
    dbgFlow(D_L7_ACCESS_CONTROL) << "About to generate Layer-7 Access Control log";

    string security_action = isPrevent() ? "Prevent" : "Detect";

    LogGen log(
        "Access Control External Vendor Reputation",
        ReportIS::Audience::SECURITY,
        ReportIS::Severity::CRITICAL,
        ReportIS::Priority::HIGH,
        ReportIS::Tags::LAYER_7_ACCESS_CONTROL
    );
    log
        << genLogField("sourcePort", HttpTransactionData::client_port_ctx)
        << genLogField("httpHostName", HttpTransactionData::host_name_ctx)
        << genLogField("httpUriPath", HttpTransactionData::uri_ctx)
        << genLogField("httpMethod", HttpTransactionData::method_ctx)
        << genLogField("ipProtocol", HttpTransactionData::http_proto_ctx)
        << genLogField("destinationPort", HttpTransactionData::listening_port_ctx)
        << genLogField("proxyIP", HttpTransactionData::proxy_ip_ctx)
        << genLogField("httpSourceId", HttpTransactionData::source_identifier)
        << genLogField("httpUriPath", HttpTransactionData::uri_path_decoded)
        << genLogField("httpUriQuery", HttpTransactionData::uri_query_decoded)
        << genLogField("httpRequestHeaders", HttpTransactionData::req_headers)
        << genLogIPField("destinationIP", HttpTransactionData::listening_ip_ctx)
        << LogField("securityAction", security_action)
        << LogField("sourceIP", source_ip)
        << LogField("externalVendorName", "CrowdSec")
        << LogField("waapIncidentType", "CrowdSec")
        << LogField("practiceSubType", "Web Access Control")
        << LogField("practiceType", "Access Control")
        << ip_reputation.getCrowdsecEventId()
        << ip_reputation.getType()
        << ip_reputation.getOrigin()
        << ip_reputation.getIpv4Address()
        << ip_reputation.getScenario();

    if (isPrevent()) {
        dbgTrace(D_L7_ACCESS_CONTROL) << "Dropping IP: " << source_ip;
        return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
    }

    dbgTrace(D_L7_ACCESS_CONTROL) << "Detecting IP: " << source_ip;
    return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
}

Maybe<LogField, Context::Error>
Layer7AccessControl::Impl::genLogField(const string &log_key, const string &env_key) const
{
    auto value = i_env->get<string>(env_key);
    if (value.ok()) return LogField(log_key, *value);
    return value.passErr();
}

Maybe<LogField, Context::Error>
Layer7AccessControl::Impl::genLogIPField(const string &log_key, const string &env_key) const
{
    auto value = i_env->get<IPAddr>(env_key);
    if (value.ok()) {
        stringstream value_str;
        value_str << value.unpack();
        return LogField(log_key, value_str.str());
    }
    return value.passErr();
}

void
Layer7AccessControl::Impl::init()
{
    registerListener();
    i_env = Singleton::Consume<I_Environment>::by<Layer7AccessControl>();
    i_intelligence = Singleton::Consume<I_Intelligence_IS_V2>::by<Layer7AccessControl>();
    i_mainloop = Singleton::Consume<I_MainLoop>::by<Layer7AccessControl>();

    chrono::minutes expiration(
        getProfileAgentSettingWithDefault<uint>(60u, "layer7AccessControl.crowdsec.cacheExpiration")
    );

    ip_reputation_cache.startExpiration(
        expiration,
        i_mainloop,
        Singleton::Consume<I_TimeGet>::by<Layer7AccessControl>()
    );
}

void
Layer7AccessControl::Impl::fini()
{
    unregisterListener();
    ip_reputation_cache.endExpiration();
}

Layer7AccessControl::Layer7AccessControl() : Component("Layer-7 Access Control"), pimpl(make_unique<Impl>()) {}

Layer7AccessControl::~Layer7AccessControl() {}

void
Layer7AccessControl::init()
{
    pimpl->init();
}

void
Layer7AccessControl::fini()
{
    pimpl->fini();
}
