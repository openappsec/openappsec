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

#include "reputation_features_agg.h"

#include <cereal/types/set.hpp>
#include <boost/algorithm/string.hpp>

#include "i_mainloop.h"
#include "i_time_get.h"
#include "i_serialize.h"
#include "../waap_clib/Waf2Util.h"
#include "customized_cereal_map.h"

USE_DEBUG_FLAG(D_WAAP_REPUTATION);

using namespace std;

template <typename EventType>
class DefaultListener : public Listener<EventType>
{
public:
    DefaultListener(EventVerdict defaultVerdict = EventVerdict(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT))
            :
        m_default_verdict(defaultVerdict)
    {}

    EventVerdict
    respond(const EventType &event)
    {
        this->upon(event);
        return m_default_verdict;
    }

private:
    EventVerdict m_default_verdict;
};

class ReputationFeaturesAgg::Impl
        :
    public Listener<IdentifiersEvent>,
    public Listener<DetectionEvent>,
    public Listener<TearDownEvent>,
    public DefaultListener<NewHttpTransactionEvent>,
    public DefaultListener<HttpRequestHeaderEvent>,
    public DefaultListener<ResponseCodeEvent>
{
public:
    Impl()
            :
        DefaultListener<ResponseCodeEvent>(EventVerdict(ngx_http_cp_verdict_e::TRAFFIC_VERDICT_IRRELEVANT)),
        m_agg_entries()
        {
        }

    void reportReputationFeatures();

    void
    init()
    {
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<ReputationFeaturesAgg>();

        if (agentDetails->getOrchestrationMode() != OrchestrationMode::ONLINE) {
            return;
        }
        registerListener();
        I_MainLoop* i_mainLoop = Singleton::Consume<I_MainLoop>::by<ReputationFeaturesAgg>();
        I_MainLoop::Routine routine = [this]() { reportReputationFeatures(); };
        i_mainLoop->addOneTimeRoutine(I_MainLoop::RoutineType::Offline, routine, "report reputation features");
    }

    void
    fini()
    {
        I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<ReputationFeaturesAgg>();

        if (agentDetails->getOrchestrationMode() != OrchestrationMode::ONLINE) {
            return;
        }
        unregisterListener();
    }

    void upon(const IdentifiersEvent &event) override;
    void upon(const DetectionEvent &event) override;
    void upon(const TearDownEvent &event) override;

    void upon(const NewHttpTransactionEvent &event) override;
    void upon(const HttpRequestHeaderEvent &event) override;
    void upon(const ResponseCodeEvent &event) override;

    string getListenerName() const { return "reputationFeaturesAgg"; }

private:
    map<string, map<string, SourceReputationFeaturesAgg>> m_agg_entries;
};

void
SourceReputationFeaturesAgg::addEntry(const ReputationFeaturesEntry &entry)
{
    m_requests++;
    if (m_wall_time_hour == 0) {
        chrono::hours wallTimeHour = chrono::duration_cast<chrono::hours>(entry.getTime());
        m_wall_time_hour = wallTimeHour.count();
    }
    addMethod(entry.getMethod());
    addResponseCode(entry.getResponseCode());
    addDetections(entry.getDetections());
    addUri(entry.getUri());
    addHeaders(entry);
    dbgTrace(D_WAAP_REPUTATION) << "aggregated request from: " << m_wall_time_hour % 24 <<
        " count: " << m_requests << " for source: " << entry.getSourceId() << " on asset: " << entry.getAssetId();
}

string
SourceReputationFeaturesAgg::extractCookieKey(const string &cookie_seg)
{
    size_t pos = cookie_seg.find("=");
    return cookie_seg.substr(0, pos);
}

void
SourceReputationFeaturesAgg::addHeaders(const ReputationFeaturesEntry &entry)
{
    const auto &headers = entry.getHeaders();

    const auto &user_agent_header_itr = headers.find("user-agent");
    if (user_agent_header_itr != headers.cend()) {
        m_unique_user_agent.insert(user_agent_header_itr->second);
    }

    const auto &referer_header_itr = headers.find("referer");
    if (referer_header_itr == headers.cend() || referer_header_itr->second.empty()) {
        m_referer_count.na++;
    } else {
        const string &uri = referer_header_itr->second;
        size_t scheme_end_pos = uri.find("://");
        if (scheme_end_pos != string::npos) {
            string authority;
            scheme_end_pos = scheme_end_pos + 3;
            size_t authority_end_pos = uri.find("/", scheme_end_pos);
            if (authority_end_pos == string::npos) {
                authority = uri.substr(scheme_end_pos);
            } else {
                authority = uri.substr(scheme_end_pos, authority_end_pos - scheme_end_pos);
            }

            if (authority.find(entry.getHost()) != string::npos) {
                m_referer_count.internal_host++;
            } else {
                m_referer_count.external_host++;
            }
        } else {
            m_referer_count.external_host++;
            dbgTrace(D_WAAP_REPUTATION) << "No scheme found in referer header: " << uri;
        }
    }

    const auto &cookie_header_itr = headers.find("cookie");
    if (cookie_header_itr == headers.cend()) {
        return;
    }
    const string &cookie = cookie_header_itr->second;
    const vector<string> &cookie_split = split(cookie, ';');
    for (const auto& cookie_seg : cookie_split)
    {
        const string &key = extractCookieKey(cookie_seg);
        m_unique_cookies.insert(key);
    }
}

void
SourceReputationFeaturesAgg::addDetections(const vector<DetectionEvent> &detections)
{
    for (const auto &detect : detections) {
        m_hit_count_per_location[detect.getLocation()]++;
    }
}

void
SourceReputationFeaturesAgg::addUri(const string &uri)
{
    size_t pos = uri.find_first_of("?;");
    if (pos == string::npos) {
        m_unique_uris.insert(uri);
        return;
    }
    string uri_path = uri.substr(0, pos);
    m_unique_uris.insert(uri_path);
}

void
SourceReputationFeaturesAgg::addMethod(const string &method)
{
    m_method_count[method]++;
}

void
SourceReputationFeaturesAgg::addResponseCode(const ResponseCode &responseCode)
{
    if (responseCode >= 500) {
        m_response_code_count.response_5xx++;
    } else if (responseCode >= 400) {
        m_response_code_count.response_4xx++;
    } else if (responseCode >= 300) {
        m_response_code_count.response_3xx++;
    } else if (responseCode >= 200) {
        m_response_code_count.response_2xx++;
    } else if (responseCode >= 100) {
        m_response_code_count.response_1xx++;
    } else {
        m_response_code_count.response_na++;
    }
}

class ReputationFeaturesReport : public RestGetFile
{
    using SourceAggPerAsset = map<string, map<string, SourceReputationFeaturesAgg>>;
public:
    ReputationFeaturesReport(SourceAggPerAsset &entries) :
        reputation_entries(entries)
    {
    }

private:
    C2S_PARAM(SourceAggPerAsset, reputation_entries);
};

void
ReputationFeaturesAgg::Impl::upon(const IdentifiersEvent &event)
{
    I_Table *pTable = Singleton::Consume<I_Table>().by<ReputationFeaturesAgg>();
    if (!pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgWarning(D_WAAP_REPUTATION) << "reputation entry state is missing";
        return;
    }
    ReputationFeaturesEntry &entry = pTable->getState<ReputationFeaturesEntry>();

    entry.m_assetId = event.getAssetId();
    entry.m_sourceId = event.getSourceId();
    dbgTrace(D_WAAP_REPUTATION) << "assign identifiers to reputation entry. src: " << event.getSourceId() <<
        ", asset: " << event.getAssetId();
}

void
ReputationFeaturesAgg::Impl::upon(const DetectionEvent &event)
{
    I_Table *pTable = Singleton::Consume<I_Table>().by<ReputationFeaturesAgg>();
    if (!pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgWarning(D_WAAP_REPUTATION) << "reputation entry state is missing";
        return;
    }
    ReputationFeaturesEntry &entry = pTable->getState<ReputationFeaturesEntry>();

    entry.m_detections.push_back(event);
    dbgTrace(D_WAAP_REPUTATION) << "add a detection event. detection location: " << event.getLocation();
}

void
ReputationFeaturesAgg::Impl::upon(const TearDownEvent &event)
{
    dbgDebug(D_WAAP_REPUTATION) << "aggregating reputation entry data";
    ReputationFeaturesEntry *entry = event.getEntry();

    SourceReputationFeaturesAgg &srvAgg = m_agg_entries[entry->getAssetId()][entry->getSourceId()];
    srvAgg.addEntry(*entry);
}

void
ReputationFeaturesAgg::Impl::upon(const NewHttpTransactionEvent &event)
{
    dbgDebug(D_WAAP_REPUTATION) << "new transaction";
    I_Table *pTable = Singleton::Consume<I_Table>().by<ReputationFeaturesAgg>();
    if (pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgDebug(D_WAAP_REPUTATION) << "reputation entry state already exists";
        return;
    }
    if (!pTable->createState<ReputationFeaturesEntry>())
    {
        dbgError(D_WAAP_REPUTATION) << "failed to create reputation entry state";
        return;
    }

    if (!pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgWarning(D_WAAP_REPUTATION) << "reputation entry state is missing";
        return;
    }
    ReputationFeaturesEntry& entry = pTable->getState<ReputationFeaturesEntry>();

    I_TimeGet *timeGet = Singleton::Consume<I_TimeGet>::by<ReputationFeaturesAgg>();
    auto currentTime = timeGet->getWalltime();
    entry.m_wallTime = currentTime;
    entry.m_method = event.getHttpMethod();
    entry.m_uri = event.getURI();
    entry.m_host = event.getDestinationHost();
    dbgTrace(D_WAAP_REPUTATION) << "created a new reputation entry state";
}

void
ReputationFeaturesAgg::Impl::upon(const HttpRequestHeaderEvent &event)
{
    I_Table *pTable = Singleton::Consume<I_Table>().by<ReputationFeaturesAgg>();
    if (!pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgWarning(D_WAAP_REPUTATION) << "reputation entry state is missing";
        return;
    }
    ReputationFeaturesEntry &entry = pTable->getState<ReputationFeaturesEntry>();
    std::string key = event.getKey();
    boost::algorithm::to_lower(key);
    entry.m_headers[key] = event.getValue();
    dbgTrace(D_WAAP_REPUTATION) << "add header: " << string(event.getKey());
}

void
ReputationFeaturesAgg::Impl::upon(const ResponseCodeEvent &event)
{
    I_Table *pTable = Singleton::Consume<I_Table>().by<ReputationFeaturesAgg>();
    if (!pTable->hasState<ReputationFeaturesEntry>())
    {
        dbgWarning(D_WAAP_REPUTATION) << "reputation entry state is missing";
        return;
    }
    ReputationFeaturesEntry &entry = pTable->getState<ReputationFeaturesEntry>();
    entry.m_responseCode = event.getResponseCode();
    dbgTrace(D_WAAP_REPUTATION) << "add response code: " << entry.getResponseCode();
}

void
ReputationFeaturesAgg::Impl::reportReputationFeatures()
{
    I_TimeGet *timeGet = Singleton::Consume<I_TimeGet>::by<ReputationFeaturesAgg>();
    I_Messaging *msg = Singleton::Consume<I_Messaging>::by<ReputationFeaturesAgg>();
    I_AgentDetails *agentDetails = Singleton::Consume<I_AgentDetails>::by<ReputationFeaturesAgg>();
    I_MainLoop *i_mainLoop = Singleton::Consume<I_MainLoop>::by<ReputationFeaturesAgg>();

    string tenantId = agentDetails->getTenantId();
    if (tenantId.empty())
    {
        tenantId = "Elpis";
    }
    string agentId = agentDetails->getAgentId();
    if (Singleton::exists<I_InstanceAwareness>())
    {
        I_InstanceAwareness *instance = Singleton::Consume<I_InstanceAwareness>::by<ReputationFeaturesAgg>();
        Maybe<string> uniqueId = instance->getUniqueID();
        if (uniqueId.ok())
        {
            agentId += "/" + uniqueId.unpack();
        }
    }
    while (true)
    {
        auto currentTime = timeGet->getWalltime();
        chrono::microseconds remainingTime = chrono::hours(1) - (currentTime % chrono::hours(1));
        i_mainLoop->yield(remainingTime);

        dbgDebug(D_WAAP_REPUTATION) << "sending features report";

        ReputationFeaturesReport report(m_agg_entries);
        m_agg_entries.clear();
        string uri = "/storage/waap/" + tenantId + "/reputation/" +
            to_string(chrono::duration_cast<chrono::hours>(currentTime).count()) +
            "/" + agentId + "/data.data";
        msg->sendObjectWithPersistence(report,
            I_Messaging::Method::PUT,
            uri,
            "",
            true,
            MessageTypeTag::WAAP_LEARNING);
    }
}

ReputationFeaturesAgg::ReputationFeaturesAgg() : Component("ReputationComp"), pimpl(make_unique<Impl>())
{
}

ReputationFeaturesAgg::~ReputationFeaturesAgg()
{
}

void
ReputationFeaturesAgg::init()
{
    pimpl->init();
}

void
ReputationFeaturesAgg::fini()
{
    pimpl->fini();
}
