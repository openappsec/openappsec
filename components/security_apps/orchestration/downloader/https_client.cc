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

#include "https_client.h"

#include <fstream>
#include <string>
#include <iostream>
#include <chrono>

#include "config.h"
#include "curl_client.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);
USE_DEBUG_FLAG(D_HTTP_REQUEST);

// LCOV_EXCL_START Reason: Depends on real download server.
Maybe<void>
HTTPSClient::getFile(const URLParser &url, const string &out_file, bool auth_required)
{
    auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<OrchestrationComp>();
    auto load_env_proxy = proxy_config->loadProxy();
    if (!load_env_proxy.ok()) return load_env_proxy;

    string token = "";
    if (auth_required) {
        token = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>()->getAccessToken();
    }

    if (!url.isOverSSL()) return genError("URL is not over SSL.");

    if (getFileSSLDirect(url, out_file, token).ok()) return Maybe<void>();
    dbgWarning(D_ORCHESTRATOR) << "Failed to get file over SSL directly. Trying indirectly.";

    if (getFileSSL(url, out_file, token).ok()) return Maybe<void>();
    dbgWarning(D_ORCHESTRATOR) << "Failed to get file over SSL. Trying via CURL (SSL).";

    //CURL fallback
    return curlGetFileOverSSL(url, out_file, token);
}

string
HTTPSClient::loadCAChainDir()
{
    string ca_chain_dir;
    auto agent_details = Singleton::Consume<I_AgentDetails>::by<OrchestrationComp>();
    auto load_ca_chain_dir = agent_details->getOpenSSLDir();
    if (load_ca_chain_dir.ok()) {
        ca_chain_dir = load_ca_chain_dir.unpack();
    }
    return getConfigurationWithDefault<string>(ca_chain_dir, "message", "Certificate authority directory");
}

Maybe<void>
HTTPSClient::getFileSSL(const URLParser &url, const string &out_file, const string &)
{
    auto downlaod_file = Singleton::Consume<I_Messaging>::by<OrchestrationComp>()->downloadFile(
        HTTPMethod::GET,
        url.getQuery(),
        out_file
    );
    if (!downlaod_file.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to get file over SSL. Error: " << downlaod_file.getErr().toString();
        return genError(downlaod_file.getErr().toString());
    }
    return Maybe<void>();
}

Maybe<void>
HTTPSClient::curlGetFileOverSSL(const URLParser &url, const string &out_file, const string &token)
{
    try {
        string cert_file_path;
        if (!token.empty()) {
            cert_file_path = getConfigurationWithDefault<string>(
                getFilesystemPathConfig() + "/certs/fog.pem",
                "message",
                "Certificate chain file path"
            );
        }

        auto proxy_config = Singleton::Consume<I_ProxyConfiguration>::by<OrchestrationComp>();
        ofstream out_file_stream(out_file, ofstream::out | ofstream::binary);

        HttpsCurl ssl_curl_client(
            url,
            out_file_stream,
            token,
            proxy_config->getProxyDomain(ProxyProtocol::HTTPS),
            proxy_config->getProxyPort(ProxyProtocol::HTTPS),
            proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS),
            cert_file_path);

        ssl_curl_client.setCurlOpts();
        bool connection_ok = ssl_curl_client.connect();
        if (!connection_ok) {
            stringstream url_s;
            url_s << url;
            string err_msg = string("Failed to get file over HTTPS. URL: ") + url_s.str();
            return genError(err_msg);
        }

    } catch (const exception &e) {
        dbgWarning(D_HTTP_REQUEST) << "Failed to get file over HTTPS. Error:" << string(e.what());
        string error_str = "Failed to get file over HTTPS, exception: " + string(e.what());
        return genError(error_str);
    }

    return Maybe<void>();
}
// LCOV_EXCL_STOP
