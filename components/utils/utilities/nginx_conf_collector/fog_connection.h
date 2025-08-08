#ifndef __FOG_CONNECTION_H__
#define __FOG_CONNECTION_H__

#include <string>
#include <vector>
#include <map>
#include "services_sdk/interfaces/i_http_client.h"
#include "req_res_objects.h"
#include "maybe_res.h"

class FogConnection
{
public:
    FogConnection(const std::string& token, const std::string& fog_address);

    void setProxy(const std::string& hosts);
    Maybe<void> getCredentials();
    Maybe<void> getJWT();
    Maybe<void> uploadNginxConfig(const std::string& config_file_path);

private:
    std::string var_token;
    std::string var_fog;
    std::string agent_id;
    std::string tenant_id;
    std::string profile_id;
    std::string ra_token;
    std::string clientId;
    std::string clientSecret;
    std::unique_ptr<I_HttpClient> curl_client;
};

#endif // __FOG_CONNECTION_H__
