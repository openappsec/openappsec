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

#ifndef __FOG_AUTHENTICATOR_H__
#define __FOG_AUTHENTICATOR_H__

#include <chrono>
#include <functional>
#include <tuple>
#include <vector>
#include <algorithm>
#include <map>
#include "cereal/archives/json.hpp"

#include "i_update_communication.h"
#include "i_orchestration_tools.h"
#include "i_agent_details.h"
#include "i_orchestration_status.h"
#include "i_messaging.h"
#include "i_mainloop.h"
#include "i_encryptor.h"
#include "i_details_resolver.h"
#include "i_rest_api.h"
#include "i_time_get.h"
#include "i_encryptor.h"
#include "maybe_res.h"

class FogAuthenticator
        :
    public I_UpdateCommunication,
    Singleton::Consume<I_RestApi>,
    Singleton::Consume<I_AgentDetails>,
    Singleton::Consume<I_DetailsResolver>,
    Singleton::Consume<I_OrchestrationStatus>,
    Singleton::Consume<I_OrchestrationTools>,
    Singleton::Consume<I_Encryptor>,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_Messaging>,
    Singleton::Consume<I_TimeGet>
{
    class AccessToken
    {
    public:
        AccessToken(const std::string &token, std::chrono::seconds expiration);

        std::chrono::seconds getRemainingTime() const;

        const std::string & getToken() const { return token; }
        uint getExpiration() const { return expiration.count(); }

    private:
        std::string token;
        std::chrono::seconds expiration;
        std::chrono::microseconds received_time;
    };

    class AccessTokenProvider : public ServerRest
    {
    public:
        void doCall() override;
        static std::function<Maybe<AccessToken>()> getAccessToken;

    private:
        S2C_PARAM(std::string, token);
        S2C_PARAM(uint, expiration);
    };

public:
    class RegistrationData
    {
        enum class AuthenticationType { Token, PresharedSecret, COUNT };

    public:
        RegistrationData() = default;
        RegistrationData(const RegistrationData &) = default;
        RegistrationData(const std::string &_env_token);

        void serialize(cereal::JSONOutputArchive &out_ar) const;
        void serialize(cereal::JSONInputArchive &in_ar);

    private:
        AuthenticationType type;
        std::string data;
    };

    FogAuthenticator() = default;
    ~FogAuthenticator() = default;

    virtual void init();

    static void preload();

    Maybe<void> authenticateAgent() override;
    void setAddressExtenesion(const std::string &extension) override;

protected:
    class UserCredentials
    {
    public:
        UserCredentials() = default;
        UserCredentials(const std::string &client_id, const std::string &shared_secret);

        std::string getClientId() const { return client_id; }
        std::string getSharedSecret() const { return shared_secret; }

        void serialize(cereal::JSONOutputArchive &out_ar) const;
        void serialize(cereal::JSONInputArchive &in_ar);

    private:
        std::string client_id;
        std::string shared_secret;
    };

    void loadRequiredSecurityApps();
    Maybe<AccessToken> getAccessToken(const UserCredentials &credentials) const;
    Maybe<UserCredentials>
    registerAgent(
        const RegistrationData &reg_data,
        const std::string &name,
        const std::string &type,
        const std::string &platform,
        const std::string &architecture
    ) const;

    void initRestAPI();
    Maybe<UserCredentials> getCredentials();

    bool saveCredentialsToFile(const UserCredentials &credentials) const;
    Maybe<UserCredentials> getCredentialsFromFile() const;
    Maybe<RegistrationData> getRegistrationData();

    std::string base64Encode(const std::string &in) const;
    std::string buildBasicAuthHeader(const std::string &username, const std::string &pass) const;
    std::string buildOAuth2Header(const std::string &token) const;
    std::string getUserEdition() const;

    // This apps which the orchestrations requires them from Fog.
    std::vector<std::string> required_security_apps;
    std::string fog_address_ex                  = "";
    std::string filesystem_prefix               = "";
    std::string otp                             = "";
    Maybe<UserCredentials> credentials          = genError("User credentials are empty");
    Maybe<AccessToken> access_token             = genError("Access token was not received yet");
    Maybe<RegistrationData> reg_data            = genError("Registration data is empty");
    I_MainLoop::RoutineID routine               = 0;
};

class AdditionalMetaData
{
public:
    AdditionalMetaData() = default;
    AdditionalMetaData(const AdditionalMetaData &) = default;

    AdditionalMetaData &
    operator<<(const std::pair<std::string, std::string> &data)
    {
        additional_data.insert(data);
        return *this;
    }

    void
    serialize(cereal::JSONOutputArchive &out_ar) const
    {
        for (auto &data : additional_data) {
            out_ar(cereal::make_nvp(data.first, data.second));
        }
    }

private:
    std::map<std::string, std::string> additional_data;
};

class RegistrationRequest : public ClientRest
{
private:
    class MetaData
    {
    public:
        MetaData() = default;
        MetaData(
            const std::string &_name,
            const std::string &_type,
            const std::string &_platform,
            const std::string &_architecture,
            const std::string &_agent_version)
                :
            name(_name),
            type(_type),
            platform(_platform),
            architecture(_architecture),
            agent_version(_agent_version)
        {
        }

        void
        serialize(cereal::JSONOutputArchive &out_ar) const
        {
            out_ar(
                cereal::make_nvp("agentName",          name),
                cereal::make_nvp("agentType",          type),
                cereal::make_nvp("platform",           platform),
                cereal::make_nvp("architecture",       architecture),
                cereal::make_nvp("agentVersion",       agent_version),
                cereal::make_nvp("additionalMetaData", additional_metadata)
            );
        }

        AdditionalMetaData &
        operator<<(const std::pair<std::string, std::string> &data)
        {
            return additional_metadata << data;
        }

    private:
        std::string name;
        std::string type;
        std::string platform;
        std::string architecture;
        std::string agent_version;
        AdditionalMetaData additional_metadata;
    };

public:
    RegistrationRequest(
        const FogAuthenticator::RegistrationData &reg_data,
        const std::string &name,
        const std::string &type,
        const std::string &platform,
        const std::string &architecture,
        const std::string &agent_version)
            :
        authenticationData({ reg_data }),
        metaData(MetaData(name, type, platform, architecture, agent_version))
    {
    }

    AdditionalMetaData &
    operator<<(const std::pair<std::string, std::string> &data)
    {
        return metaData.get() << data;
    }

    std::string getClientId() const { return client_id; }
    std::string getSharedSecret() const { return shared_secret; }
    std::string getAgentId() const { return agentId; }
    std::string getProfileId() const { return profileId; }
    std::string getTenantId() const { return tenantId; }

private:
    C2S_PARAM(std::vector<FogAuthenticator::RegistrationData>, authenticationData);
    C2S_PARAM(MetaData, metaData);

    S2C_PARAM(std::string, client_id);
    S2C_PARAM(std::string, shared_secret);
    S2C_PARAM(std::string, tenantId);
    S2C_PARAM(std::string, profileId);
    S2C_PARAM(std::string, agentId);
};

class PolicyVersionPatchRequest
{
public:
    PolicyVersionPatchRequest(const std::string &_policy_version, const std::string &_policy_versions)
            :
        policy_version(_policy_version),
        policy_versions(_policy_versions)
    {
    }

    Maybe<std::string>
    genJson() const
    {
        return "{ \"policyVersion\" :\"" + policy_version + "\", \"versions\": " + policy_versions + "}";
    }

private:
    std::string policy_version;
    std::string policy_versions;
};

class TokenRequest : public ClientRest
{
public:
    std::string getAccessToken()     const { return access_token; }
    std::string getTokenType()       const { return token_type; }
    std::string getUserId()          const { return user_id; }
    std::string getScope()           const { return scope; }
    std::string getJTI()             const { return jti; }
    int getExpirationTime()     const { return expires_in; }

private:
    S2C_PARAM(int,    expires_in);
    S2C_PARAM(std::string, jti);
    S2C_PARAM(std::string, scope);
    S2C_PARAM(std::string, token_type);
    S2C_PARAM(std::string, access_token);
    S2C_LABEL_PARAM(std::string, user_id, "uuid");
};

#endif // __FOG_AUTHENTICATOR_H__
