#ifndef __REQ_RES_OBJECTS_H__
#define __REQ_RES_OBJECTS_H__

#include "cereal/archives/json.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/map.hpp"

#include "debug.h"

USE_DEBUG_FLAG(D_NGINX_MANAGER);

struct AgentRegistrationRequest
{
    struct AuthData
    {
        template<class Archive>
        void serialize(Archive& ar)
        {
            try {
                ar(cereal::make_nvp("authenticationMethod", authenticationMethod));
                ar(cereal::make_nvp("data", data));
            } catch (const cereal::Exception &e) {
                dbgWarning(D_NGINX_MANAGER) << "Serialization error in AuthData: " << e.what();
                ar.setNextName(nullptr);
            }
        }
        
        std::string authenticationMethod;
        std::string data;
    };
    
    struct MetaData
    {
        template<class Archive>
        void serialize(Archive& ar)
        {
            try {
                ar(cereal::make_nvp("agentName", agentName));
                ar(cereal::make_nvp("agentType", agentType));
                ar(cereal::make_nvp("platform", platform));
                ar(cereal::make_nvp("architecture", architecture));
                for (const auto& pair : additionalMetaData) {
                    ar(cereal::make_nvp(pair.first.c_str(), pair.second));
                }
            } catch (const cereal::Exception &e) {
                dbgWarning(D_NGINX_MANAGER) << "Serialization error in MetaData: " << e.what();
                ar.setNextName(nullptr);
            }
        }
        
        std::string agentName;
        std::string agentType;
        std::string platform;
        std::string architecture;
        std::map<std::string, std::string> additionalMetaData;
    };
    
    template<class Archive>
    void serialize(Archive& ar)
    {
        try {
            ar(cereal::make_nvp("authenticationData", authenticationData));
            ar(cereal::make_nvp("metaData", metaData));
        } catch (const cereal::Exception &e) {
            dbgWarning(D_NGINX_MANAGER) << "Serialization error in AgentRegistrationRequest: " << e.what();
            ar.setNextName(nullptr);
        }
    }
    
    std::vector<AuthData> authenticationData;
    MetaData metaData;
};

struct TokenRequest
{
    template<class Archive>
    void serialize(Archive& ar)
    {
        try {
            ar(cereal::make_nvp("login", login));
            ar(cereal::make_nvp("password", password));
        } catch (const cereal::Exception &e) {
            dbgWarning(D_NGINX_MANAGER) << "Serialization error in TokenRequest: " << e.what();
            ar.setNextName(nullptr);
        }
    }
    
    std::string login;
    std::string password;
};

struct AgentRegistrationResponse
{
    template<class Archive>
    void serialize(Archive& ar)
    {
        try {
            ar(cereal::make_nvp("agentId", agentId));
            ar(cereal::make_nvp("clientId", clientId));
            ar(cereal::make_nvp("clientSecret", clientSecret));
            ar(cereal::make_nvp("tenantId", tenantId));
            ar(cereal::make_nvp("profileId", profileId));
        } catch (const cereal::Exception &e) {
            dbgWarning(D_NGINX_MANAGER) << "Serialization error in AgentRegistrationResponse: " << e.what();
            ar.setNextName(nullptr);
        }
    }
    
    std::string agentId;
    std::string clientId;
    std::string clientSecret;
    std::string tenantId;
    std::string profileId;
};

struct TokenResponse
{
    template<class Archive>
    void serialize(Archive& ar)
    {
        try {
            ar(cereal::make_nvp("access_token", access_token));
        } catch (const cereal::Exception &e) {
            dbgWarning(D_NGINX_MANAGER) << "Serialization error in TokenResponse: " << e.what();
            ar.setNextName(nullptr);
        }
    }
    
    std::string access_token;
};
#endif
