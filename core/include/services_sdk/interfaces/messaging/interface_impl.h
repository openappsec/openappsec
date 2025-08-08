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
#ifndef __INTERFACE_IMPL_H__
#define __INTERFACE_IMPL_H__

#ifndef __I_MESSAGING_H__
#error "interface_impl.h should not be included directly"
#endif // __I_MESSAGING_H__

USE_DEBUG_FLAG(D_MESSAGING);

MessageMetadata::MessageMetadata(bool immediate_tracing)
{
    if (immediate_tracing && Singleton::exists<I_Environment>()) {
        insertHeaders(Singleton::Consume<I_Environment>::by<MessageMetadata>()->getCurrentHeadersMap());
    }

    if (!Singleton::exists<I_AgentDetails>() || !Singleton::exists<I_ProxyConfiguration>()) return;
    auto i_agent_details = Singleton::Consume<I_AgentDetails>::by<I_Messaging>();
    auto i_proxy_configuration = Singleton::Consume<I_ProxyConfiguration>::by<I_Messaging>();

    is_to_fog = true;
    host_name = i_agent_details->getFogDomain().ok() ? i_agent_details->getFogDomain().unpack() : "";
    port_num = i_agent_details->getFogPort().ok() ? i_agent_details->getFogPort().unpack() : 0;

    ProxyProtocol protocol = i_agent_details->getSSLFlag() ? ProxyProtocol::HTTPS : ProxyProtocol::HTTP;

    auto maybe_proxy_domain = i_proxy_configuration->getProxyDomain(protocol);
    std::string proxy_domain = maybe_proxy_domain.ok() ? *maybe_proxy_domain : "";

    dbgTrace(D_MESSAGING) << "Created message metadata. Host name: " << host_name << ", Port num: " << port_num;
    if (proxy_domain.empty()) return;

    auto maybe_proxy_port = i_proxy_configuration->getProxyPort(protocol);
    uint16_t proxy_port = maybe_proxy_port.ok() ? *maybe_proxy_port : 0;

    auto maybe_proxy_auth = i_proxy_configuration->getProxyAuthentication(protocol);
    std::string proxy_auth = maybe_proxy_auth.ok() ? *maybe_proxy_auth : "";

    setProxySettings(MessageProxySettings(proxy_domain, proxy_auth, proxy_port));

    dbgTrace(D_MESSAGING) << "Proxy : " << proxy_domain <<  ":" << proxy_port;
}

template <typename serializableObject>
Maybe<void, HTTPResponse>
I_Messaging::sendSyncMessage(
    HTTPMethod method,
    const std::string &uri,
    serializableObject &req_obj,
    MessageCategory category,
    MessageMetadata message_metadata)
{
    Maybe<std::string> req_body = req_obj.genJson();
    if (!req_body.ok()) {
        return genError(
            HTTPResponse(
                HTTPStatusCode::NO_HTTP_RESPONSE,
                "Failed to create a request. Error: " + req_body.getErr()
            )
        );
    }

    Maybe<HTTPResponse, HTTPResponse> response_data = sendSyncMessage(
        method,
        uri,
        req_body.unpack(),
        category,
        message_metadata
    );
    if (!response_data.ok()) return response_data.passErr();

    auto res_obj = req_obj.loadJson(response_data.unpack().getBody());
    if (!res_obj) {
        return genError(
            HTTPResponse(
                HTTPStatusCode::NO_HTTP_RESPONSE,
                "Failed to parse response body. Body: " + response_data.unpack().getBody()
            )
        );
    }
    return {};
}

template <typename serializableObject>
bool
I_Messaging::sendSyncMessageWithoutResponse(
    const HTTPMethod method,
    const std::string &uri,
    serializableObject &req_obj,
    const MessageCategory category,
    MessageMetadata message_metadata)
{
    Maybe<std::string> req_body = req_obj.genJson();
    if (!req_body.ok()) {
        dbgWarning(D_MESSAGING) << "Failed to create a request. Error: " << req_body.getErr();
        return false;
    }

    Maybe<HTTPResponse, HTTPResponse> response_data = sendSyncMessage(
        method,
        uri,
        req_body.unpack(),
        category,
        message_metadata
    );
    if (!response_data.ok()) {
        dbgWarning(D_MESSAGING)
            << "Received error from server. Status code: "
            << int(response_data.getErr().getHTTPStatusCode())
            << ", error response: "
            << response_data.getErr().getBody();
        return false;
    }
    return true;
}

template <typename serializableObject>
void
I_Messaging::sendAsyncMessage(
    const HTTPMethod method,
    const std::string &uri,
    serializableObject &req_obj,
    const MessageCategory category,
    MessageMetadata message_metadata,
    bool force_buffering)
{
    Maybe<std::string> req_body = req_obj.genJson();
    if (!req_body.ok()) {
        dbgWarning(D_MESSAGING) << "Failed to create a request. Error: " << req_body.getErr();
        return;
    }

    dbgTrace(D_MESSAGING) << "Sending async message. URI: " << uri << ", Body: " << req_body.unpack();

    sendAsyncMessage(
        method,
        uri,
        req_body.unpack(),
        category,
        message_metadata,
        force_buffering
    );
}

#endif // __INTERFACE_IMPL_H__
