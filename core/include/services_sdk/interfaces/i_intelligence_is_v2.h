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

#ifndef __I_INTELLIGENCE_IS_V2_H__
#define __I_INTELLIGENCE_IS_V2_H__

#include <chrono>
#include <string>

#include "maybe_res.h"
#include "i_messaging.h"
#include "i_time_get.h"
#include "i_mainloop.h"
#include "intelligence_is_v2/intelligence_types_v2.h"
#include "intelligence_is_v2/intelligence_query_v2.h"
#include "config.h"

namespace Intelligence {

class Invalidation;

} // namespace Intelligence

class I_Intelligence_IS_V2
{
public:
    virtual bool sendInvalidation(const Intelligence::Invalidation &invalidation) const = 0;
    virtual Maybe<uint> registerInvalidation(
        const Intelligence::Invalidation &invalidation,
        const std::function<void(const Intelligence::Invalidation &)> &callback
    ) = 0;
    virtual void unregisterInvalidation(uint id) = 0;

    template<typename Data>
    Maybe<std::vector<AssetReply<Data>>>
    queryIntelligence(QueryRequest &query_request, bool ignore_in_progress = false, bool is_pretty = true)
    {
        uint assets_limit = query_request.getAssetsLimit();
        static const uint upper_assets_limit = 50;
        if (assets_limit == 0 || assets_limit > upper_assets_limit) {
            return genError("Assets limit must be in the range of [1, " + std::to_string(upper_assets_limit) + "]");
        }

        static const uint upper_confidence_limit = 1000;
        bool min_conf_res = query_request.checkMinConfidence(upper_confidence_limit);
        if (!min_conf_res) {
            return genError(
                "Minimum confidence value must be in the range of [1, " + std::to_string(upper_confidence_limit) + "]"
            );
        }

        if (query_request.isPagingActivated() && query_request.isPagingFinished()) {
            return genError("Paging is activated and already finished. No need for more queries.");
        }

        IntelligenceQuery<Data> intelligence_query(query_request, is_pretty);
        static const std::string query_uri = "/api/v2/intelligence/assets/query";

        bool res = getIsOfflineOnly() ? false : sendQueryObject(intelligence_query, query_uri, assets_limit);
        if (!res) {
            dbgTrace(D_INTELLIGENCE) << "Could not message fog, trying to get offline intelligence.";
            Maybe<std::string> offline_res = getOfflineInfoString(query_request.getQuery());
            if (!offline_res.ok()) {
                dbgDebug(D_INTELLIGENCE) << "Offline intelligence error: " << offline_res.getErr();
                return genError("Could not query intelligence");
            }
            if (!intelligence_query.loadJson(offline_res.unpack())) {
                dbgWarning(D_INTELLIGENCE) << "Offline intelligence error: invalid JSON for requested asset";
                return genError("Could not query intelligence");
            }
        }

        if (ignore_in_progress && intelligence_query.getResponseStatus() == ResponseStatus::IN_PROGRESS) {
            return genError("Query intelligence response with InProgress status");
        }
        return intelligence_query.getData();
    }

    template<typename Data>
    Maybe<std::vector<Maybe<std::vector<AssetReply<Data>>>>>
    queryIntelligence(std::vector<QueryRequest> &query_requests, bool is_pretty = true)
    {
        static const uint upper_assets_limit = 50;
        static const uint upper_confidence_limit = 1000;
        for (QueryRequest &query_request : query_requests) {
            uint assets_limit = query_request.getAssetsLimit();
            if (assets_limit == 0 || assets_limit > upper_assets_limit) {
                dbgTrace(D_INTELLIGENCE)
                    << "Assets limit for request is "
                    << upper_assets_limit
                    << ", requests assets: "
                    << assets_limit;
                return genError("Assets limit valid range is of [1, " + std::to_string(upper_assets_limit) + "]");
            }

            bool min_conf_res = query_request.checkMinConfidence(upper_confidence_limit);
            if (!min_conf_res) {
                dbgTrace(D_INTELLIGENCE) << "Illegal confidence value";
                return genError(
                    "Minimum confidence value valid range is of [1, " + std::to_string(upper_confidence_limit) + "]"
                );
            }
        }
        IntelligenceQuery<Data> intelligence_query(query_requests, is_pretty);
        static const std::string query_uri = "/api/v2/intelligence/assets/queries";

        dbgTrace(D_INTELLIGENCE) << "Sending intelligence bulk request with " << query_requests.size() << " items";
        bool res = getIsOfflineOnly() ? false : sendQueryObject(intelligence_query, query_uri, upper_assets_limit);
        if (!res) {
            dbgTrace(D_INTELLIGENCE) << "Could not message fog, bulk request failed.";
            return genError("Could not query intelligence");
        }

        return intelligence_query.getBulkData();
    }

private:
    template<typename Data>
    bool
    sendMessage(
        IntelligenceQuery<Data> &intelligence_query,
        const std::string &query_uri,
        I_Messaging *i_message,
        Flags<MessageConnConfig> conn_flags,
        const std::string &ip,
        uint server_port
    ) {
        if (ip == "" && server_port == 0) {
            return i_message->sendObject(
                intelligence_query,
                I_Messaging::Method::POST,
                query_uri,
                "",
                nullptr,
                true,
                MessageTypeTag::INTELLIGENCE
            );
        }

        dbgTrace(D_INTELLIGENCE)
            << "Sending intelligence request with IP: "
            << ip
            << " port: "
            << server_port
            << " query_uri: "
            << query_uri;

        return i_message->sendObject(
            intelligence_query,
            I_Messaging::Method::POST,
            ip,
            server_port,
            conn_flags,
            query_uri,
            "",
            nullptr,
            MessageTypeTag::INTELLIGENCE
        );
    }

    template<typename Data>
    bool
    sendQueryMessage(
        IntelligenceQuery<Data> &intelligence_query,
        const std::string &query_uri,
        I_Messaging *i_message,
        Flags<MessageConnConfig> conn_flags,
        const std::string &ip = "",
        uint server_port = 0
    ) {
        auto i_timer = getTimer();
        auto i_mainloop = getMainloop();

        uint request_overall_timeout_conf = getConfigurationWithDefault<uint>(
            20,
            "intelligence",
            "request overall timeout"
        );

        uint request_lap_timeout_conf = getConfigurationWithDefault<uint>(
            5,
            "intelligence",
            "request lap timeout"
        );

        std::chrono::seconds request_overall_timeout = std::chrono::seconds(request_overall_timeout_conf);
        std::chrono::seconds request_lap_timeout = std::chrono::seconds(request_lap_timeout_conf);

        std::chrono::microseconds send_request_start_time = i_timer->getMonotonicTime();
        std::chrono::microseconds last_lap_time = i_timer->getMonotonicTime();
        std::chrono::seconds seconds_since_start = std::chrono::seconds(0);
        std::chrono::seconds seconds_since_last_lap = std::chrono::seconds(0);

        bool res = true;
        while (res &&
            intelligence_query.getResponseStatus() == ResponseStatus::IN_PROGRESS &&
            seconds_since_start < request_overall_timeout &&
            seconds_since_last_lap < request_lap_timeout
        ) {
            res = sendMessage(intelligence_query, query_uri, i_message, conn_flags, ip, server_port);

            if (res && intelligence_query.getResponseStatus() == ResponseStatus::IN_PROGRESS) {
                i_mainloop->yield(true);
            }

            seconds_since_start = std::chrono::duration_cast<std::chrono::seconds>(
                i_timer->getMonotonicTime() - send_request_start_time
            );

            seconds_since_last_lap = std::chrono::duration_cast<std::chrono::seconds>(
                i_timer->getMonotonicTime() - last_lap_time
            );
            last_lap_time = i_timer->getMonotonicTime();
        }

        return res;
    }

    template<typename Data>
    bool
    sendPagingQueryMessage(
        IntelligenceQuery<Data> &intelligence_query,
        const std::string &query_uri,
        int assets_limit,
        I_Messaging *i_message,
        Flags<MessageConnConfig> conn_flags,
        const std::string &ip = "",
        uint server_port = 0
    ) {
        bool res= true;

        res = sendMessage(intelligence_query, query_uri, i_message, conn_flags, ip, server_port);

        if (intelligence_query.getResponseStatus() == ResponseStatus::DONE &&
            intelligence_query.getResponseAssetCollectionsSize() < assets_limit
        ) {
            intelligence_query.setRequestCursor(Intelligence_IS_V2::CursorState::DONE, "");
        } else {
            intelligence_query.setRequestCursor(
                Intelligence_IS_V2::CursorState::IN_PROGRESS,
                intelligence_query.getResponseCursorVal()
            );
        }

        return res;
    }

// LCOV_EXCL_START Reason: one templated instance is tested in intelligence ut. the rest are tested in system tests
    template<typename Data>
    bool
    sendQueryObjectToLocalServer(
        IntelligenceQuery<Data> &intelligence_query,
        const std::string &query_uri,
        const std::string &ip,
        bool is_primary_port,
        int assets_limit,
        I_Messaging *i_message,
        Flags<MessageConnConfig> conn_flags
    ) {
        static const std::string primary_port_setting = "local intelligence server primary port";
        static const std::string secondary_port_setting = "local intelligence server secondary port";
        auto server_port = getSetting<uint>(
            "intelligence",
            is_primary_port ? primary_port_setting : secondary_port_setting
        );

        if (!server_port.ok()) return false;

        conn_flags.reset();
        
        if (intelligence_query.getPagingStatus().ok()) {
            return sendPagingQueryMessage(
                intelligence_query,
                query_uri,
                assets_limit,
                i_message,
                conn_flags,
                ip,
                *server_port
            );
        }

        return sendQueryMessage(intelligence_query, query_uri, i_message, conn_flags, ip, *server_port);
    }
// LCOV_EXCL_STOP

    template<typename Data>
    bool
    sendQueryObject(IntelligenceQuery<Data> &intelligence_query, const std::string &query_uri, int assets_limit)
    {
        auto i_message = getMessaging();
        Flags<MessageConnConfig> conn_flags;

        bool crowdsec_enabled = std::getenv("CROWDSEC_ENABLED") ?
            std::string(std::getenv("CROWDSEC_ENABLED")) == "true" :
            false;

        crowdsec_enabled = getProfileAgentSettingWithDefault<bool>(
            crowdsec_enabled,
            "layer7AccessControl.crowdsec.enabled"
        );

        bool use_local_intelligence = getProfileAgentSettingWithDefault<bool>(
            false,
            "agent.config.useLocalIntelligence"
        );

        auto server_ip = getSetting<std::string>("intelligence", "local intelligence server ip");
        if (server_ip.ok() && (use_local_intelligence || crowdsec_enabled)) {
            if (sendQueryObjectToLocalServer(
                    intelligence_query,
                    query_uri,
                    *server_ip,
                    true,
                    assets_limit,
                    i_message,
                    conn_flags
                )
            ) {
                return true;
            }
            if (sendQueryObjectToLocalServer(
                    intelligence_query,
                    query_uri,
                    *server_ip,
                    false,
                    assets_limit,
                    i_message,
                    conn_flags
                )
            ) {
                return true;
            };
        }

        if (intelligence_query.getPagingStatus().ok()) {
            return sendPagingQueryMessage(intelligence_query, query_uri, assets_limit, i_message, conn_flags);
        }

        return sendQueryMessage(intelligence_query, query_uri, i_message, conn_flags);
    }

    virtual I_Messaging * getMessaging() const = 0;
    virtual I_TimeGet * getTimer() const = 0;
    virtual I_MainLoop * getMainloop() const = 0;
    virtual Maybe<std::string> getOfflineInfoString(const SerializableQueryFilter &query) const = 0;
    virtual bool getIsOfflineOnly() const = 0;
};
#endif // __I_INTELLIGENCE_IS_V2_H__
