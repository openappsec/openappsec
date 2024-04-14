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
#include "intelligence_server.h"
#include "config.h"
#include "debug.h"
#include "enum_array.h"
#include "intelligence_comp_v2.h"

USE_DEBUG_FLAG(D_INTELLIGENCE);

using namespace Intelligence;
using namespace std;

static const string query_uri = "/api/v2/intelligence/assets/query";
static const string queries_uri = "/api/v2/intelligence/assets/queries";
static const string primary_port_setting = "local intelligence server primary port";
static const string secondary_port_setting = "local intelligence server secondary port";

Sender::Sender(IntelligenceRequest request) : request(request)
{
    i_message = Singleton::Consume<I_Messaging>::by<IntelligenceComponentV2>();
    i_timer = Singleton::Consume<I_TimeGet>::by<IntelligenceComponentV2>();
    i_mainloop = Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();
    bool crowdsec_enabled = std::getenv("CROWDSEC_ENABLED") ?
                                                            std::string(std::getenv("CROWDSEC_ENABLED")) == "true" :
                                                            false;
    if (getProfileAgentSettingWithDefault<bool>(crowdsec_enabled, "layer7AccessControl.crowdsec.enabled")) {
        is_local_intelligence = true;
    }

    if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.useLocalIntelligence")) {
        is_local_intelligence = true;
    }

    auto setting_server_ip = getSetting<string>("intelligence", "local intelligence server ip");
    if (setting_server_ip.ok() && is_local_intelligence) server_ip = *setting_server_ip;
}

Maybe<Response>
Sender::sendIntelligenceRequest()
{
    if (server_ip.ok() && is_local_intelligence) {
        auto response = sendQueryObjectToLocalServer(true);
        if (response.ok()) return response;
        dbgWarning(D_INTELLIGENCE) << "Failed to send query to primary port. Error" << response.getErr();
        response = sendQueryObjectToLocalServer(false);
        if (response.ok()) return response;
        dbgWarning(D_INTELLIGENCE) << "Failed to send query to secondary port. Error" << response.getErr();
    }

    if (request.getPagingStatus().ok()) {
        return sendMessage();
    }

    return sendQueryMessage();
}

Maybe<Response>
Sender::sendQueryObjectToLocalServer(bool is_primary_port)
{
    auto local_port =  getSetting<uint>(
        "intelligence",
        is_primary_port ? primary_port_setting : secondary_port_setting
    );

    if (!local_port.ok()) return genError(
        "Failed to send intelligence query to local server. Config Error number:"
        + to_string(static_cast<uint>(local_port.getErr()))
    );

    server_port = *local_port;
    conn_flags.reset();
    conn_flags.setFlag(MessageConnectionConfig::UNSECURE_CONN);

    auto res = sendQueryMessage();

    server_port = genError("port unset after use");

    return res;
}

Maybe<Response>
Sender::sendQueryMessage()
{
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

    chrono::seconds request_overall_timeout = chrono::seconds(request_overall_timeout_conf);
    chrono::seconds request_lap_timeout = chrono::seconds(request_lap_timeout_conf);

    chrono::microseconds send_request_start_time = i_timer->getMonotonicTime();
    chrono::microseconds last_lap_time = i_timer->getMonotonicTime();
    chrono::seconds seconds_since_start = chrono::seconds(0);
    chrono::seconds seconds_since_last_lap = chrono::seconds(0);

    Maybe<Response> res = genError("Uninitialized");
    do {
        res = sendMessage();

        if (res.ok() && res->getResponseStatus() == ResponseStatus::IN_PROGRESS) {
            i_mainloop->yield(true);
        }

        seconds_since_start = std::chrono::duration_cast<std::chrono::seconds>(
            i_timer->getMonotonicTime() - send_request_start_time
        );

        seconds_since_last_lap = std::chrono::duration_cast<std::chrono::seconds>(
            i_timer->getMonotonicTime() - last_lap_time
        );
        last_lap_time = i_timer->getMonotonicTime();
    } while (res.ok() &&
        res->getResponseStatus() == ResponseStatus::IN_PROGRESS &&
        seconds_since_start < request_overall_timeout &&
        seconds_since_last_lap < request_lap_timeout
    );

    return res;
}

Maybe<Response>
Sender::sendMessage()
{
    if (server_port.ok() && !server_ip.ok()) return genError("Can't send intelligence request. Server ip invalid");
    if (server_ip.ok() && !server_port.ok()) return genError("Can't send intelligence request. Server port invalid");
    auto req_md = server_ip.ok() ? MessageMetadata(*server_ip, *server_port, conn_flags) : MessageMetadata();

    if (server_ip.ok()) {
        dbgTrace(D_INTELLIGENCE)
            << "Sending intelligence request with IP: "
            << *server_ip
            << " port: "
            << *server_port
            << " query_uri: "
            << (request.isBulk() ? queries_uri : query_uri);
    }

    auto json_body = request.genJson();
    if (!json_body.ok()) return json_body.passErr();
    auto req_data = i_message->sendSyncMessage(
        HTTPMethod::POST,
        request.isBulk() ? queries_uri : query_uri,
        *json_body,
        MessageCategory::INTELLIGENCE,
        req_md
    );
    if (!req_data.ok()) {
        auto response_error = req_data.getErr().toString();
        dbgWarning(D_INTELLIGENCE) << "Failed to send intelligence request. Error:" << response_error;
        return genError(
            "Failed to send intelligence request. "
            + req_data.getErr().getBody()
            + " "
            + req_data.getErr().toString()
        );
    } else if (req_data->getHTTPStatusCode() != HTTPStatusCode::HTTP_OK) {
        return genError("Intelligence response is invalid. " + req_data->toString());
    }

    return createResponse(req_data->getBody());
}

Maybe<Response>
Sender::createResponse(const std::string &response_body)
{
    Response response(response_body, request.getSize(), request.isBulk());
    auto load_status = response.load();
    if (!load_status.ok()) return load_status.passErr();
    return response;
}
