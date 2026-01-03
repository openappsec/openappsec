#include "http_geo_filter.h"

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <algorithm>
#include <sstream>
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>

#include "cidrs_data.h"
#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/parameters_config.h"
#include "generic_rulebase/triggers_config.h"
#include "user_identifiers_config.h"
#include "debug.h"
#include "config.h"
#include "rest.h"
#include "geo_config.h"
#include "ip_utilities.h"
#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_GEO_FILTER);

static const LogTriggerConf default_triger;

class HttpGeoFilter::Impl : public Listener<HttpRequestHeaderEvent>
{
public:

    void
    init()
    {
        dbgTrace(D_GEO_FILTER) << "Init Http Geo filter component";
        handleNewPolicy();
        registerConfigLoadCb([this]() { handleNewPolicy(); });
    }

    void
    fini()
    {
        unregisterListener();
    }

    void
    handleNewPolicy()
    {
        if (ParameterException::isGeoLocationExceptionExists()) {
            registerListener();
            return;
        }

        if (!ParameterException::isGeoLocationExceptionExists()) {
            unregisterListener();
        }
    }

    string getListenerName() const override { return "HTTP geo filter"; }

    void
    loadDefaultAction()
    {
        auto default_action_maybe = getProfileAgentSetting<string>("httpGeoFilter.defaultAction");
        if(default_action_maybe.ok()) {
            default_action = convertActionToVerdict(default_action_maybe.unpack());
            dbgTrace(D_GEO_FILTER)
                << "Load http geo filter default action. Action: "
                << default_action_maybe.unpack();
        } else {
            default_action = ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
            dbgTrace(D_GEO_FILTER) << "No http geo filter default action. Action: Irrelevant";
        }
    }

    EventVerdict
    respond(const HttpRequestHeaderEvent &event) override
    {
        dbgTrace(D_GEO_FILTER) << getListenerName() << " new transaction event";

        if (!event.isLastHeader()) return EventVerdict(ServiceVerdict::TRAFFIC_VERDICT_INSPECT);
        std::set<std::string> ip_set;
        auto env = Singleton::Consume<I_Environment>::by<HttpGeoFilter>();
        auto maybe_xff = env->get<std::string>(HttpTransactionData::xff_vals_ctx);
        if (!maybe_xff.ok()) {
            dbgTrace(D_GEO_FILTER) << "failed to get xff vals from env";
        } else {
            ip_set = split(maybe_xff.unpack(), ',');
        }
        dbgDebug(D_GEO_FILTER) << getListenerName() << " last header, start lookup";

        if (ip_set.size() > 0) {
            removeTrustedIpsFromXff(ip_set);
        } else {
            dbgDebug(D_GEO_FILTER) << "xff not found in headers";
        }

        auto maybe_source_ip = env->get<IPAddr>(HttpTransactionData::client_ip_ctx);
        if (!maybe_source_ip.ok()) {
            dbgWarning(D_GEO_FILTER) << "failed to get source ip from env";
            return EventVerdict(default_action);
        }
        auto source_ip = convertIpAddrToString(maybe_source_ip.unpack());

        // saas profile setting
        bool ignore_source_ip =
            getProfileAgentSettingWithDefault<bool>(false, "agent.geoProtaction.ignoreSourceIP");
        if (ignore_source_ip){
            dbgDebug(D_GEO_FILTER) << "Geo protection ignoring source ip: " << source_ip;
        } else {
            dbgTrace(D_GEO_FILTER) << "Geo protection source ip: " << source_ip;
            ip_set.insert(convertIpAddrToString(maybe_source_ip.unpack()));
        }


        ServiceVerdict exception_verdict = getExceptionVerdict(ip_set);
        if (exception_verdict != ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT) {
            return EventVerdict(exception_verdict);
        }

        // deprecated for now
        // ServiceVerdict geo_lookup_verdict = getGeoLookupVerdict(ip_set);
        // if (geo_lookup_verdict != ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT) {
        //     return EventVerdict(geo_lookup_verdict);
        // }

        return EventVerdict(default_action);
    }

private:
    std::set<std::string>
    split(const std::string& s, char delim) {
        std::set<std::string> elems;
        std::stringstream ss(s);
        std::string value;
        while (std::getline(ss, value, delim)) {
            elems.insert(trim(value));
        }
        return elems;
    }

    static inline std::string &ltrim(std::string &s) {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(),
            [] (char c) { return !std::isspace(c); }));
        return s;
    }

    // trim from end
    static inline std::string &rtrim(std::string &s) {
        s.erase(std::find_if(s.rbegin(), s.rend(),
            [] (char c) { return !std::isspace(c); }).base(), s.end());
        return s;
    }

    // trim from both ends
    static inline std::string &trim(std::string &s) {
        return ltrim(rtrim(s));
    }

    void
    removeTrustedIpsFromXff(std::set<std::string> &xff_set)
    {
        auto identify_config = getConfigurationWithCache<UsersAllIdentifiersConfig>(
            "rulebase",
            "usersIdentifiers"
        );
        if (!identify_config.ok()) {
            dbgDebug(D_GEO_FILTER) << "did not find users identifiers definition in policy";
        } else {
            auto trusted_ips = (*identify_config).getHeaderValuesFromConfig("x-forwarded-for");
            for (auto it = xff_set.begin(); it != xff_set.end();) {
                if (isIpTrusted(*it, trusted_ips)) {
                    dbgTrace(D_GEO_FILTER) << "xff value is in trusted ips: " << *it;
                    it = xff_set.erase(it);
                } else {
                    dbgTrace(D_GEO_FILTER) << "xff value is not in trusted ips: " << *it;
                    ++it;
                }
            }
        }
    }

    bool
    isIpTrusted(const string &ip, const vector<string> &trusted_ips)
    {
        for (const auto &trusted_ip : trusted_ips) {
            CIDRSData cidr_data(trusted_ip);
            if (
                ip == trusted_ip ||
                (cidr_data.contains(ip))
            ) {
                return true;
            }
        }
        return false;
    }

    string
    convertIpAddrToString(const IPAddr &ip_to_convert)
    {
        ostringstream os;
        os << ip_to_convert;
        return os.str();
    }

    ServiceVerdict
    convertBehaviorValueToVerdict(const BehaviorValue &behavior_value) const
    {
            if (behavior_value == BehaviorValue::ACCEPT || behavior_value == BehaviorValue::IGNORE) {
                return ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
            }
            if (behavior_value == BehaviorValue::DROP  || behavior_value == BehaviorValue::REJECT) {
                return ServiceVerdict::TRAFFIC_VERDICT_DROP;
            }
        return ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
    }

    // LCOV_EXCL_START Reason: deprecated for now
    ServiceVerdict
    convertActionToVerdict(const string &action) const
    {
        if (action == "accept") return ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
        if (action == "drop") return ServiceVerdict::TRAFFIC_VERDICT_DROP;
        return ServiceVerdict::TRAFFIC_VERDICT_INSPECT;
    }

    ServiceVerdict
    getGeoLookupVerdict(const std::set<std::string> &sources)
    {
        auto maybe_geo_config = getConfiguration<GeoConfig>("rulebase", "httpGeoFilter");
        if (!maybe_geo_config.ok()) {
            dbgTrace(D_GEO_FILTER) << "Failed to load HTTP Geo Filter config. Error:" << maybe_geo_config.getErr();
            return ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
        }
        GeoConfig geo_config = maybe_geo_config.unpack();
        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data;
        I_GeoLocation *i_geo_location = Singleton::Consume<I_GeoLocation>::by<HttpGeoFilter>();

        for (const std::string& source : sources) {
            Maybe<IPAddr> maybe_source_ip = IPAddr::createIPAddr(source);
            if (!maybe_source_ip.ok()){
                dbgWarning(D_GEO_FILTER) <<
                "create ip address failed for source: " <<
                source <<
                ", Error: " <<
                maybe_source_ip.getErr();
                continue;
            }
            auto asset_location = i_geo_location->lookupLocation(maybe_source_ip.unpack());
            if (!asset_location.ok()) {
                dbgWarning(D_GEO_FILTER) <<
                "Lookup location failed for source: " <<
                source <<
                ", Error: " <<
                asset_location.getErr();
                continue;
            }

            geo_location_data = asset_location.unpack();

            string country_code = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE];

            if (geo_config.isAllowedCountry(country_code)) {
                dbgTrace(D_GEO_FILTER)
                    << "geo verdict ACCEPT, practice id: "
                    << geo_config.getId()
                    << ", country code: "
                    << country_code;
                generateVerdictLog(
                    ServiceVerdict::TRAFFIC_VERDICT_ACCEPT,
                    geo_config.getId(),
                    true,
                    geo_location_data
                );
                return ServiceVerdict::TRAFFIC_VERDICT_ACCEPT;
            }
            if (geo_config.isBlockedCountry(country_code)) {
                dbgTrace(D_GEO_FILTER)
                    << "geo verdict DROP, practice id: "
                    << geo_config.getId()
                    << ", country code: "
                    << country_code;
                generateVerdictLog(
                    ServiceVerdict::TRAFFIC_VERDICT_DROP,
                    geo_config.getId(),
                    true,
                    geo_location_data
                );
                return ServiceVerdict::TRAFFIC_VERDICT_DROP;
            }
        }
        dbgTrace(D_GEO_FILTER)
            << "No matched practice. Returned default action: "
            << geo_config.getDefaultAction();
        generateVerdictLog(
            convertActionToVerdict(geo_config.getDefaultAction()),
            geo_config.getId(),
            true,
            geo_location_data,
            true
        );
        return convertActionToVerdict(geo_config.getDefaultAction());
    }
    // LCOV_EXCL_STOP

    Maybe<pair<ServiceVerdict, string>>
    getBehaviorsVerdict(
        const unordered_map<string, set<string>> &behaviors_map_to_search,
        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data)
    {
        bool is_matched = false;
        ParameterBehavior matched_behavior;
        ServiceVerdict matched_verdict = ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
        I_GenericRulebase *i_rulebase = Singleton::Consume<I_GenericRulebase>::by<HttpGeoFilter>();
        set<ParameterBehavior> behaviors_set = i_rulebase->getBehavior(behaviors_map_to_search);
        dbgTrace(D_GEO_FILTER) << "get verdict from: " << behaviors_set.size() << " behaviors";
        for (const ParameterBehavior &behavior : behaviors_set) {
            matched_verdict = convertBehaviorValueToVerdict(behavior.getValue());
            if (
                matched_verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP
            ){
                dbgTrace(D_GEO_FILTER) << "behavior verdict: DROP, exception id: " << behavior.getId();
                generateVerdictLog(
                    matched_verdict,
                    behavior.getId(),
                    false,
                    geo_location_data
                );
                return pair<ServiceVerdict, string>(matched_verdict, behavior.getId());
            }
            else if (
                matched_verdict == ServiceVerdict::TRAFFIC_VERDICT_ACCEPT
            ){
                dbgTrace(D_GEO_FILTER) << "behavior verdict: ACCEPT, exception id: " << behavior.getId();
                matched_behavior = behavior;
                is_matched = true;
            }
        }
        if (is_matched) {
            return pair<ServiceVerdict, string>(
                ServiceVerdict::TRAFFIC_VERDICT_ACCEPT,
                matched_behavior.getId()
            );
        }
        return genError("No exception matched to HTTP geo filter rule");
    }

    ServiceVerdict
    getExceptionVerdict(const std::set<std::string> &sources) {

        pair<ServiceVerdict, string> curr_matched_behavior;
        ServiceVerdict verdict = ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
        I_GeoLocation *i_geo_location = Singleton::Consume<I_GeoLocation>::by<HttpGeoFilter>();
        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data;
        auto env = Singleton::Consume<I_Environment>::by<HttpGeoFilter>();
        string source_id;
        auto maybe_source_id = env->get<std::string>(HttpTransactionData::source_identifier);
        if (!maybe_source_id.ok()) {
            dbgTrace(D_GEO_FILTER) << "failed to get source identifier from env";
        } else {
            source_id = maybe_source_id.unpack();
        }

        for (const std::string& source : sources) {

            Maybe<IPAddr> maybe_source_ip = IPAddr::createIPAddr(source);
            if (!maybe_source_ip.ok()){
                dbgWarning(D_GEO_FILTER) <<
                "create ip address failed for source: " <<
                source <<
                ", Error: " <<
                maybe_source_ip.getErr();
                continue;
            }


            auto asset_location = i_geo_location->lookupLocation(maybe_source_ip.unpack());
            if (!asset_location.ok()) {
                dbgDebug(D_GEO_FILTER) << "Lookup location failed for source: " <<
                source <<
                ", Error: " <<
                asset_location.getErr();
                continue;
            }
            geo_location_data = asset_location.unpack();
            string country_code = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE];
            string country_name = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_NAME];
            dbgTrace(D_GEO_FILTER)
            << "Get exception verdict. "
            << "country code: "
            << country_code
            << ", country name: "
            << country_name
            << ", ip address: "
            << source
            << ", source identifier: "
            << source_id;


            unordered_map<string, set<string>> exception_value_country_code = {
                {"countryCode", {country_code}},
                {"sourceIdentifier", {source_id}}
            };
            auto matched_behavior_maybe = getBehaviorsVerdict(exception_value_country_code, geo_location_data);
            if (matched_behavior_maybe.ok()) {
                curr_matched_behavior = matched_behavior_maybe.unpack();
                verdict = curr_matched_behavior.first;
                if (verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
                    return verdict;
                }
            }

            unordered_map<string, set<string>> exception_value_country_name = {
                {"countryName", {country_name}},
                {"sourceIdentifier", {source_id}}
            };
            matched_behavior_maybe = getBehaviorsVerdict(exception_value_country_name, geo_location_data);
            if (matched_behavior_maybe.ok()) {
                curr_matched_behavior = matched_behavior_maybe.unpack();
                verdict = curr_matched_behavior.first;
                if (verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP) {
                    return verdict;
                }
            }
        }

        if (verdict == ServiceVerdict::TRAFFIC_VERDICT_ACCEPT) {
            generateVerdictLog(
                verdict,
                curr_matched_behavior.second,
                false,
                geo_location_data
            );
        }
        return verdict;
    }

    void
    generateVerdictLog(
        const ServiceVerdict &verdict,
        const string &matched_id,
        bool is_geo_filter,
        const EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data,
        bool is_default_action = false
    )
    {
        dbgTrace(D_GEO_FILTER) << "Generate Log for verdict - HTTP geo filter";
        auto &trigger = getConfigurationWithDefault(default_triger, "rulebase", "log");
        bool is_prevent = verdict == ServiceVerdict::TRAFFIC_VERDICT_DROP;
        string matched_on = is_geo_filter ? "geoFilterPracticeId" : "exceptionId";
        LogGen log = trigger(
            "Web Request - HTTP Geo Filter",
            LogTriggerConf::SecurityType::ThreatPrevention,
            ReportIS::Severity::MEDIUM,
            ReportIS::Priority::HIGH,
            is_prevent,
            LogField("practiceType", "HTTP Geo Filter"),
            LogField(matched_on, matched_id),
            ReportIS::Tags::HTTP_GEO_FILTER
        );
        auto env = Singleton::Consume<I_Environment>::by<HttpGeoFilter>();
        auto source_ip = env->get<IPAddr>(HttpTransactionData::client_ip_ctx);
        if (source_ip.ok()) log << LogField("sourceIP", convertIpAddrToString(source_ip.unpack()));

        auto source_identifier = env->get<string>(HttpTransactionData::source_identifier);
        if (source_identifier.ok()) log << LogField("httpSourceId", source_identifier.unpack());

        auto source_port = env->get<string>(HttpTransactionData::client_port_ctx);
        if (source_port.ok()) log << LogField("sourcePort", source_port.unpack());

        auto host_name = env->get<string>(HttpTransactionData::host_name_ctx);
        if (host_name.ok()) log << LogField("hostName", host_name.unpack());

        auto method = env->get<string>(HttpTransactionData::method_ctx);
        if (method.ok()) log << LogField("httpMethod", method.unpack());

        log << LogField("securityAction", is_prevent ? "Prevent" : "Detect");

        if (is_default_action) log << LogField("isDefaultSecurityAction", true);
        auto xff = env->get<string>(HttpTransactionData::xff_vals_ctx);
        if (xff.ok()) log << LogField("proxyIP", xff.unpack());

        log
            << LogField("sourceCountryCode", geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE])
            << LogField("sourceCountryName", geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_NAME]);
    }

    ServiceVerdict default_action = ServiceVerdict::TRAFFIC_VERDICT_IRRELEVANT;
};

HttpGeoFilter::HttpGeoFilter() : Component("HttpGeoFilter"), pimpl(make_unique<HttpGeoFilter::Impl>()) {}
HttpGeoFilter::~HttpGeoFilter() {}

void
HttpGeoFilter::init()
{
    pimpl->init();
}

void
HttpGeoFilter::fini()
{
    pimpl->fini();
}

void
HttpGeoFilter::preload()
{
    registerExpectedConfiguration<GeoConfig>("rulebase", "httpGeoFilter");
    registerExpectedConfigurationWithCache<UsersAllIdentifiersConfig>("assetId", "rulebase", "usersIdentifiers");
    registerConfigLoadCb([this]() { pimpl->loadDefaultAction(); });
}
