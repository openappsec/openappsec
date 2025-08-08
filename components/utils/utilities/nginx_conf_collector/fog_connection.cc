#include "fog_connection.h"

#include <sstream>
#include <fstream>
#include <iostream>
#include <cereal/archives/json.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/string.hpp>
#include "debug.h"
#include "internal/curl_http_client.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_MANAGER);

// Helper function to check if HTTPResponse indicates success
bool
isSuccessfulResponse(const HTTPResponse& response)
{
    HTTPStatusCode code = response.getHTTPStatusCode();
    return (code == HTTPStatusCode::HTTP_OK ||
            code == HTTPStatusCode::HTTP_NO_CONTENT ||
            code == HTTPStatusCode::HTTP_MULTI_STATUS);
}

FogConnection::FogConnection(const string& token, const string& fog_address)
    : var_token(token), var_fog(fog_address), curl_client(std::make_unique<CurlHttpClient>()) {}

void
FogConnection::setProxy(const string& hosts)
{
    curl_client->setProxy(hosts);
}

Maybe<void>
FogConnection::getCredentials()
{
    AgentRegistrationRequest request;
    AgentRegistrationRequest::AuthData auth;

    auth.authenticationMethod = "token";
    auth.data = var_token;

    request.authenticationData.push_back(auth);
    request.metaData.agentName = "ConfCollector";
    request.metaData.agentType = "Embedded";
    request.metaData.platform = "linux";
    request.metaData.architecture = "x86";
    request.metaData.additionalMetaData["agentVendor"] = "nginx-conf-collector";

    stringstream ss_req;
    {
        cereal::JSONOutputArchive ar(ss_req);
        request.serialize(ar);
    }

    dbgTrace(D_NGINX_MANAGER) << "Registration JSON: " << ss_req.str();

    string url = var_fog + "/agents";
    map<string, string> headers = {{"Content-Type", "application/json"},
                                    {"User-Agent", "Infinity Next (a7030abf93a4c13)"}};

    auto response = curl_client->post(url, ss_req.str(), headers);

    dbgTrace(D_NGINX_MANAGER)
        << "Register agent response code: "
        << static_cast<int>(response.getHTTPStatusCode())
        << ", body: "
        << response.getBody();

    if (!isSuccessfulResponse(response)) {
        return genError("Failed to register agent: HTTP "
                        + to_string(static_cast<int>(response.getHTTPStatusCode()))
                        + " - "
                        + response.getBody());
    }

    if (response.getBody().find("referenceId") != string::npos) {
        return genError("Registration failed: " + response.getBody());
    }

    try {
        AgentRegistrationResponse reg_response;
        stringstream ss_res(response.getBody());
        cereal::JSONInputArchive ar(ss_res);
        reg_response.serialize(ar);
        
        agent_id = reg_response.agentId;
        clientId = reg_response.clientId;
        clientSecret = reg_response.clientSecret;
        tenant_id = reg_response.tenantId;
        profile_id = reg_response.profileId;
    } catch (const exception& e) {
        dbgTrace(D_NGINX_MANAGER) << "Failed to parse registration response: " << response.getBody();
        return genError("Failed to parse registration response: " + string(e.what()));
    }

    return {};
}

Maybe<void>
FogConnection::getJWT()
{
    TokenRequest request;
    request.login = clientId;
    request.password = clientSecret;

    stringstream ss_req;
    {
        cereal::JSONOutputArchive ar(ss_req);
        ar(request);
    }

    string url = var_fog + "/oauth/token?grant_type=client_credentials";
    map<string, string> headers = {{"Content-Type", "application/json"},
                                    {"User-Agent", "Infinity Next (a7030abf93a4c13)"}};

    dbgTrace(D_NGINX_MANAGER) << "get JWT JSON: " << ss_req.str();

    curl_client->setBasicAuth(clientId, clientSecret);
    curl_client->authEnabled(true);
    auto response = curl_client->post(url, ss_req.str(), headers);

    dbgTrace(D_NGINX_MANAGER)
        << "get JWT response code: "
        << static_cast<int>(response.getHTTPStatusCode())
        << ", body: "
        << response.getBody();

    if (!isSuccessfulResponse(response)) {
        return genError("Failed to get JWT: HTTP "
                        + to_string(static_cast<int>(response.getHTTPStatusCode()))
                        + " - "
                        + response.getBody());
    }

    if (response.getBody().find("referenceId") != string::npos) {
        return genError("JWT request failed: " + response.getBody());
    }

    try {
        TokenResponse token_response;
        stringstream ss_res(response.getBody());
        cereal::JSONInputArchive ar(ss_res);
        token_response.serialize(ar);
        
        ra_token = token_response.access_token;
    } catch (const exception& e) {
        dbgTrace(D_NGINX_MANAGER) << "Failed to parse JWT response: " << response.getBody();
        return genError("Failed to parse JWT response: " + string(e.what()));
    }

    return {};
}

Maybe<void>
FogConnection::uploadNginxConfig(const string& config_file_path)
{
    if (tenant_id.empty() || profile_id.empty() || ra_token.empty()) {
        return genError("Missing required data for upload: tenant_id, profile_id, or ra_token");
    }

    ifstream file(config_file_path, ios::binary);
    if (!file.is_open()) {
        return genError("Cannot open file: " + config_file_path);
    }

    string file_content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    file.close();

    if (file_content.empty()) {
        dbgTrace(D_NGINX_MANAGER) << "Warning: Uploading empty file content from " << config_file_path;
    }


    string upload_url = var_fog + "/agents-core/storage/" + tenant_id + "/nginx/" + profile_id + "/1/nginx.conf";
    map<string, string> headers = {
        {"Authorization", "Bearer " + ra_token},
        {"Content-Type", "text/plain"},
        {"User-Agent", "Infinity Next (a7030abf93a4c13)"}
    };

    auto response = curl_client->put(upload_url, file_content, headers);

    dbgTrace(D_NGINX_MANAGER)
        << "Upload status code: "
        << static_cast<int>(response.getHTTPStatusCode())
        << ", body: "
        << response.getBody();

    if (!isSuccessfulResponse(response)) {
        return genError("Upload failed: HTTP "
                        + to_string(static_cast<int>(response.getHTTPStatusCode()))
                        + " - "
                        + response.getBody());
    }

    return {};
}
