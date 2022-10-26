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

#ifndef __REPUTATION_FEATURES_AGG_H__
#define __REPUTATION_FEATURES_AGG_H__

#include <cereal/types/map.hpp>

#include "reputation_features_events.h"
#include "component.h"
#include "table_opaque.h"
#include "i_table.h"
#include "i_agent_details.h"
#include "i_instance_awareness.h"

class ReputationFeaturesEntry : public TableOpaqueSerialize<ReputationFeaturesEntry>
{
public:
    ReputationFeaturesEntry()
            :
        TableOpaqueSerialize<ReputationFeaturesEntry>(this),
        m_wallTime(),
        m_sourceId(),
        m_assetId(),
        m_method(),
        m_uri(),
        m_responseCode(),
        m_detections()
    {
    }

    ~ReputationFeaturesEntry()
    {
        TearDownEvent(this).notify();
    }

    // LCOV_EXCL_START - sync functions, can only be tested once the sync module exists

    template <typename T>
    void serialize(T &ar, uint)
    {
        ar(m_wallTime,
            m_sourceId,
            m_assetId,
            m_method,
            m_uri,
            m_host,
            m_responseCode,
            m_detections,
            m_headers);
    }

    static std::string name() { return "ReputationFeatures"; }
    static std::unique_ptr<TableOpaqueBase> prototype() { return std::make_unique<ReputationFeaturesEntry>(); }
    static uint currVer() { return 0; }
    static uint minVer() { return 0; }

    // LCOV_EXCL_STOP

    const std::chrono::microseconds & getTime() const { return m_wallTime; }
    const std::string & getSourceId() const { return m_sourceId; }
    const std::string & getAssetId() const { return m_assetId; }
    const std::string & getMethod() const { return m_method; }
    const std::string & getUri() const { return m_uri; }
    const std::string & getHost() const { return m_host; }
    const ResponseCode & getResponseCode() const { return m_responseCode; }
    const std::vector<DetectionEvent> & getDetections() const { return m_detections; }
    const std::map<std::string, std::string> & getHeaders() const { return m_headers; }

    friend class ReputationFeaturesAgg;

private:
    std::chrono::microseconds m_wallTime;
    std::string m_sourceId;
    std::string m_assetId;
    std::string m_method;
    std::string m_uri;
    std::string m_host;
    ResponseCode m_responseCode;
    std::vector<DetectionEvent> m_detections;
    std::map<std::string, std::string> m_headers;
};

typedef struct ResponseCodeCounters
{
    size_t response_na;
    size_t response_1xx;
    size_t response_2xx;
    size_t response_3xx;
    size_t response_4xx;
    size_t response_5xx;

    ResponseCodeCounters()
        :
        response_na(0),
        response_1xx(0),
        response_2xx(0),
        response_3xx(0),
        response_4xx(0),
        response_5xx(0)
    {
    }

    template<class Archive>
    void serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("response_NA", response_na),
            cereal::make_nvp("response_1xx", response_1xx),
            cereal::make_nvp("response_2xx", response_2xx),
            cereal::make_nvp("response_3xx", response_3xx),
            cereal::make_nvp("response_4xx", response_4xx),
            cereal::make_nvp("response_5xx", response_5xx)
        );
    }
} ResponseCodeCounters;

typedef struct RefererCounters
{
    size_t na;
    size_t internal_host;
    size_t external_host;

    RefererCounters()
            :
        na(0),
        internal_host(0),
        external_host(0)
    {
    }

    template<class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("referer_NA", na),
            cereal::make_nvp("internal_host", internal_host),
            cereal::make_nvp("external_host", external_host)
        );
    }
} RefererCounters;

class SourceReputationFeaturesAgg
{
public:
    SourceReputationFeaturesAgg() : m_wall_time_hour(0), m_requests(0)
    {
    }

    template<class Archive>
    void
    serialize(Archive &ar)
    {
        ar(
            cereal::make_nvp("wall_time_hour", m_wall_time_hour),
            cereal::make_nvp("requests_count", m_requests),
            cereal::make_nvp("hits_per_location", m_hit_count_per_location),
            cereal::make_nvp("method_counters", m_method_count),
            cereal::make_nvp("response_code_counters", m_response_code_count),
            cereal::make_nvp("referer_counters", m_referer_count),
            cereal::make_nvp("uris", m_unique_uris),
            cereal::make_nvp("user_agents", m_unique_user_agent),
            cereal::make_nvp("cookies", m_unique_cookies)
        );
    }

    void addEntry(const ReputationFeaturesEntry &entry);

private:
    std::string extractCookieKey(const std::string &cookie_seg);
    void addHeaders(const ReputationFeaturesEntry &entry);
    void addDetections(const std::vector<DetectionEvent> &detections);
    void addUri(const std::string &uri);
    void addMethod(const std::string &method);
    void addResponseCode(const ResponseCode &responseCode);

    size_t m_wall_time_hour;
    size_t m_requests;
    std::map<std::string, size_t> m_hit_count_per_location;
    std::map<std::string, size_t> m_method_count;
    ResponseCodeCounters m_response_code_count;
    RefererCounters m_referer_count;
    std::set<std::string> m_unique_uris;
    std::set<std::string> m_unique_user_agent;
    std::set<std::string> m_unique_cookies;
};

class ReputationFeaturesAgg
        :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Table>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_InstanceAwareness>,
    Singleton::Consume<I_Messaging>
{
public:
    ReputationFeaturesAgg();
    ~ReputationFeaturesAgg();

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __REPUTATION_FEATURES_AGG_H__
