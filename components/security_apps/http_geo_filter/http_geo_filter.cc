#include "http_geo_filter.h"

#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <algorithm>

#include "generic_rulebase/generic_rulebase.h"
#include "generic_rulebase/parameters_config.h"
#include "generic_rulebase/triggers_config.h"
#include "debug.h"
#include "config.h"
#include "rest.h"
#include "geo_config.h"
#include "ip_utilities.h"
#include "log_generator.h"

using namespace std;

USE_DEBUG_FLAG(D_GEO_FILTER);

static const LogTriggerConf default_triger;

class HttpGeoFilter::Impl : public Listener<NewHttpTransactionEvent>
{
public:
    void
    init()
    {
        dbgTrace(D_GEO_FILTER) << "Init Http Geo filter component";
        registerListener();
    }

    void
    fini()
    {
        unregisterListener();
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
            default_action = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
            dbgTrace(D_GEO_FILTER) << "No http geo filter default action. Action: Irrelevant";
        }
    }

    EventVerdict
    respond(const NewHttpTransactionEvent &event) override
    {
        dbgTrace(D_GEO_FILTER) << getListenerName() << " new transaction event";

        if (!ParameterException::isGeoLocationExceptionExists() &&
            !getConfiguration<GeoConfig>("rulebase", "httpGeoFilter").ok()
        ) {
            dbgTrace(D_GEO_FILTER) << "No geo location practice nor exception was found. Returning default verdict";
            return EventVerdict(default_action);
        }

        I_GeoLocation *i_geo_location = Singleton::Consume<I_GeoLocation>::by<HttpGeoFilter>();
        auto asset_location = i_geo_location->lookupLocation(event.getSourceIP());
        if (!asset_location.ok()) {
            dbgTrace(D_GEO_FILTER) << "Lookup location failed, Error: " << asset_location.getErr();
            return EventVerdict(default_action);
        }

        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data = asset_location.unpack();

        ngx_http_cp_verdict_e exception_verdict = getExceptionVerdict(event, geo_location_data);
        if (exception_verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT) {
            return EventVerdict(exception_verdict);
        }

        ngx_http_cp_verdict_e geo_lookup_verdict = getGeoLookupVerdict(event, geo_location_data);
        if (geo_lookup_verdict != ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT) {
            return EventVerdict(geo_lookup_verdict);
        }
        return EventVerdict(default_action);
    }

private:
    string
    convertIpAddrToString(const IPAddr &ip_to_convert)
    {
        ostringstream os;
        os << ip_to_convert;
        return os.str();
    }

    ngx_http_cp_verdict_e
    convertActionToVerdict(const string &action) const
    {
        if (action == "accept") return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
        if (action == "drop") return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
        return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;
    }

    ngx_http_cp_verdict_e
    convertBehaviorValueToVerdict(const BehaviorValue &behavior_value) const
    {
            if (behavior_value == BehaviorValue::ACCEPT || behavior_value == BehaviorValue::IGNORE) {
                return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
            }
            if (behavior_value == BehaviorValue::DROP  || behavior_value == BehaviorValue::REJECT) {
                return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
            }
        return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
    }

    ngx_http_cp_verdict_e
    getGeoLookupVerdict(
        const NewHttpTransactionEvent &event,
        const EnumArray<I_GeoLocation::GeoLocationField, std::string> &geo_location_data)
    {
        auto maybe_geo_config = getConfiguration<GeoConfig>("rulebase", "httpGeoFilter");
        if (!maybe_geo_config.ok()) {
            dbgWarning(D_GEO_FILTER) << "Failed to load HTTP Geo Filter config. Error:" << maybe_geo_config.getErr();
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
        }
        GeoConfig geo_config = maybe_geo_config.unpack();
        string country_code = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE];

        if (geo_config.isAllowedCountry(country_code)) {
            dbgTrace(D_GEO_FILTER)
                << "geo verdict ACCEPT, practice id: "
                << geo_config.getId()
                << ", country code: "
                << country_code;
            generateVerdictLog(
                ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT,
                event,
                geo_config.getId(),
                true,
                geo_location_data
            );
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
        }
        if (geo_config.isBlockedCountry(country_code)) {
            dbgTrace(D_GEO_FILTER)
                << "geo verdict DROP, practice id: "
                << geo_config.getId()
                << ", country code: "
                << country_code;
            generateVerdictLog(
                ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP,
                event,
                geo_config.getId(),
                true,
                geo_location_data
            );
            return ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
        }
        dbgTrace(D_GEO_FILTER)
            << "No matched practice. Returned default action: "
            << geo_config.getDefaultAction();
        generateVerdictLog(
            convertActionToVerdict(geo_config.getDefaultAction()),
            event,
            geo_config.getId(),
            true,
            geo_location_data,
            true
        );
        return convertActionToVerdict(geo_config.getDefaultAction());
    }

    Maybe<pair<ngx_http_cp_verdict_e, string>>
    getBehaviorsVerdict(
        const unordered_map<string, set<string>> &behaviors_map_to_search,
        const NewHttpTransactionEvent &event,
        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data)
    {
        bool is_matched = false;
        ParameterBehavior matched_behavior;
        ngx_http_cp_verdict_e matched_verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
        I_GenericRulebase *i_rulebase = Singleton::Consume<I_GenericRulebase>::by<HttpGeoFilter>();
        set<ParameterBehavior> behaviors_set = i_rulebase->getBehavior(behaviors_map_to_search);
        dbgTrace(D_GEO_FILTER) << "get verdict from: " << behaviors_set.size() << " behaviors";
        for (const ParameterBehavior &behavior : behaviors_set) {
            matched_verdict = convertBehaviorValueToVerdict(behavior.getValue());
            if (
                matched_verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP
            ){
                dbgTrace(D_GEO_FILTER) << "behavior verdict: DROP, exception id: " << behavior.getId();
                generateVerdictLog(
                    matched_verdict,
                    event,
                    behavior.getId(),
                    false,
                    geo_location_data
                );
                return pair<ngx_http_cp_verdict_e, string>(matched_verdict, behavior.getId());
            }
            else if (
                matched_verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT
            ){
                dbgTrace(D_GEO_FILTER) << "behavior verdict: ACCEPT, exception id: " << behavior.getId();
                matched_behavior = behavior;
                is_matched = true;
            }
        }
        if (is_matched) {
            return pair<ngx_http_cp_verdict_e, string>(
                ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT,
                matched_behavior.getId()
            );
        }
        return genError("No exception matched to HTTP geo filter rule");
    }

    ngx_http_cp_verdict_e
    getExceptionVerdict(
        const NewHttpTransactionEvent &event,
        EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data
    ){
        string country_code = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE];
        string country_name = geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_NAME];
        string source_ip = convertIpAddrToString(event.getSourceIP());

        pair<ngx_http_cp_verdict_e, string> curr_matched_behavior;
        ngx_http_cp_verdict_e verdict = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;

        dbgTrace(D_GEO_FILTER)
            << "Get exception verdict. "
            << "country code: "
            << country_code
            << ", country name: "
            << country_name
            << ", source ip address: "
            << source_ip;

        unordered_map<string, set<string>> exception_value_source_ip = {{"sourceIP", {source_ip}}};
        auto matched_behavior_maybe = getBehaviorsVerdict(exception_value_source_ip, event, geo_location_data);
        if (matched_behavior_maybe.ok()) {
            curr_matched_behavior = matched_behavior_maybe.unpack();
            verdict = curr_matched_behavior.first;
            if (verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP) {
                return verdict;
            }
        }

        unordered_map<string, set<string>> exception_value_country_code = {
            {"countryCode", {country_code}}
        };
        matched_behavior_maybe = getBehaviorsVerdict(exception_value_country_code, event, geo_location_data);
        if (matched_behavior_maybe.ok()) {
            curr_matched_behavior = matched_behavior_maybe.unpack();
            verdict = curr_matched_behavior.first;
            if (verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP) {
                return verdict;
            }
        }

        unordered_map<string, set<string>> exception_value_country_name = {
            {"countryName", {country_name}}
        };
        matched_behavior_maybe = getBehaviorsVerdict(exception_value_country_name, event, geo_location_data);
        if (matched_behavior_maybe.ok()) {
            curr_matched_behavior = matched_behavior_maybe.unpack();
            verdict = curr_matched_behavior.first;
            if (verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP) {
                return verdict;
            }
        }
        if (verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT) {
            generateVerdictLog(
                verdict,
                event,
                curr_matched_behavior.second,
                false,
                geo_location_data
            );
        }
        return verdict;
    }

    void
    generateVerdictLog(
        const ngx_http_cp_verdict_e &verdict,
        const NewHttpTransactionEvent &event,
        const string &matched_id,
        bool is_geo_filter,
        const EnumArray<I_GeoLocation::GeoLocationField, std::string> geo_location_data,
        bool is_default_action = false
    )
    {
        dbgTrace(D_GEO_FILTER) << "Generate Log for verdict - HTTP geo filter";
        auto &trigger = getConfigurationWithDefault(default_triger, "rulebase", "log");
        bool is_prevent = verdict == ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
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
        log
            << LogField("sourceIP", convertIpAddrToString(event.getSourceIP()))
            << LogField("sourcePort", event.getSourcePort())
            << LogField("hostName", event.getDestinationHost())
            << LogField("httpMethod", event.getHttpMethod())
            << LogField("securityAction", is_prevent ? "Prevent" : "Detect");

        if (is_default_action) log << LogField("isDefaultSecurityAction", true);

        log
            << LogField("sourceCountryCode", geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_CODE])
            << LogField("sourceCountryName", geo_location_data[I_GeoLocation::GeoLocationField::COUNTRY_NAME]);
    }

    ngx_http_cp_verdict_e default_action = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT;
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
    registerConfigLoadCb([this]() { pimpl->loadDefaultAction(); });
}
