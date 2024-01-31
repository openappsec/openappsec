#ifndef __MOCK_AGENT_DTEAILS_H__
#define __MOCK_AGENT_DTEAILS_H__

#include "i_agent_details.h"
#include "cptest.h"

class MockAgentDetails : public Singleton::Provide<I_AgentDetails>::From<MockProvider<I_AgentDetails>>
{
public:
    MOCK_METHOD1(setFogPort, void(const uint16_t));
    MOCK_METHOD1(setSSLFlag, void(const bool));
    MOCK_METHOD1(setOrchestrationMode, void(const OrchestrationMode));
    MOCK_METHOD1(setFogDomain, void(const std::string&));
    MOCK_METHOD1(setProfileId, void(const std::string&));
    MOCK_METHOD1(setTenantId, void(const std::string&));

    MOCK_CONST_METHOD0(getFogPort, Maybe<uint16_t>());
    MOCK_CONST_METHOD0(getSSLFlag, bool());
    MOCK_CONST_METHOD0(getOrchestrationMode, OrchestrationMode());
    MOCK_CONST_METHOD0(getFogDomain, Maybe<std::string>());
    MOCK_CONST_METHOD0(getTenantId, std::string());
    MOCK_CONST_METHOD0(getProfileId, std::string());

    // Agent Details
    MOCK_CONST_METHOD0(getProxy, Maybe<std::string>());
    MOCK_METHOD1(setProxy, void(const std::string&));
    MOCK_METHOD1(setAgentId, void(const std::string&));
    MOCK_CONST_METHOD0(getAgentId, std::string());
    MOCK_METHOD0(loadAccessToken, void());
    MOCK_CONST_METHOD0(getAccessToken, std::string());

    // OpenSSL
    MOCK_METHOD1(setOpenSSLDir, void(const std::string&));
    MOCK_CONST_METHOD0(getOpenSSLDir, Maybe<std::string>());

    // Serialization
    MOCK_METHOD0(readAgentDetails, bool());
    MOCK_METHOD0(writeAgentDetails, bool());

    // Environment
    MOCK_METHOD1(setClusterId, void(const std::string&));
};

#endif
