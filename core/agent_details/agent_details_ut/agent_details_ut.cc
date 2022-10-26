#include "agent_details.h"

#include "mock/mock_encryptor.h"
#include "mock/mock_shell_cmd.h"
#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "buffer.h"
#include "cptest.h"

using namespace std;
using namespace testing;

class AgentDetailsTest : public Test
{
public:
    AgentDetailsTest()
    {
        config = Singleton::Consume<Config::I_Config>::from(conf);
    }

    ::Environment env;
    ConfigComponent conf;
    StrictMock<MockEncryptor> mock_encryptor;
    StrictMock<MockShellCmd> mock_shell_cmd;
    Config::I_Config *config = nullptr;
};

TEST_F(AgentDetailsTest, doNothing)
{
}

TEST_F(AgentDetailsTest, basicTest)
{
    const vector<string> agent_details_vec {
        "{",
        "    \"Fog domain\": \"fog.com\",",
        "    \"Agent ID\": \"fdfdf-5454-dfd\",",
        "    \"Fog port\": 443,",
        "    \"Encrypted connection\": false,",
        "    \"Orchestration mode\": \"offline_mode\",",
        "    \"Tenant ID\": \"tenant_id\",",
        "    \"Profile ID\": \"profile\",",
        "    \"Proxy\": \"http://proxy.checkpoint.com/\",",
        "    \"OpenSSL certificates directory\": \"\"",
        "}"
    };
    AgentDetails agent_details;
    env.preload();
    agent_details.preload();
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput("dmidecode -s system-manufacturer | tr -d '\\n'", _, _)
    ).WillOnce(Return(string("Microsoft Corporation")));
    env.init();
    agent_details.init();

    auto i_conf = Singleton::Consume<Config::I_Config>::from(conf);
    i_conf->reloadConfiguration();

    CPTestTempfile agent_details_file(agent_details_vec);
    setConfiguration(agent_details_file.fname, "Agent details", "File path");

    EXPECT_TRUE(agent_details.readAgentDetails());
    EXPECT_EQ(agent_details.getFogDomain().unpack(), "fog.com");
    EXPECT_EQ(agent_details.getFogPort().unpack(), 443);
    EXPECT_EQ(agent_details.getAgentId(), "fdfdf-5454-dfd");
    EXPECT_FALSE(agent_details.getSSLFlag());

    agent_details.setSSLFlag(true);
    agent_details.setFogPort(80);
    agent_details.setFogDomain("fog.checkpoint.com");
    agent_details.setAgentId("dfdfdf-dfd");
    agent_details.setClusterId("d5bd7949-554e-4fac-86c3-6e4e5d46a034");
    EXPECT_EQ(agent_details.getFogDomain().unpack(), "fog.checkpoint.com");
    EXPECT_EQ(agent_details.getFogPort().unpack(), 80);
    EXPECT_EQ(agent_details.getAgentId(), "dfdfdf-dfd");
    EXPECT_EQ(agent_details.getTenantId(), "tenant_id");
    EXPECT_EQ(agent_details.getProfileId(), "profile");
    EXPECT_EQ(agent_details.getClusterId(), "d5bd7949-554e-4fac-86c3-6e4e5d46a034");

    EXPECT_TRUE(agent_details.writeAgentDetails());

    EXPECT_TRUE(agent_details.readAgentDetails());
    EXPECT_EQ(agent_details.getFogDomain().unpack(), "fog.checkpoint.com");
    EXPECT_EQ(agent_details.getFogPort().unpack(), 80);
    EXPECT_EQ(agent_details.getAgentId(), "dfdfdf-dfd");
    EXPECT_EQ(agent_details.getClusterId(), "d5bd7949-554e-4fac-86c3-6e4e5d46a034");
    EXPECT_TRUE(agent_details.getSSLFlag());
    EXPECT_THAT(agent_details.getProxy(), IsValue("http://proxy.checkpoint.com/"));
    agent_details.setProxy("none");
    EXPECT_THAT(agent_details.getProxy(), IsValue("none"));

    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::OFFLINE);
    agent_details.setOrchestrationMode(OrchestrationMode::ONLINE);
    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::ONLINE);
    auto machine_type = Singleton::Consume<I_Environment>::from(env)->get<I_AgentDetails::MachineType>("MachineType");
    EXPECT_EQ(machine_type.unpack(), I_AgentDetails::MachineType::AZURE);
}

TEST_F(AgentDetailsTest, openSSL)
{
    const vector<string> agent_details_vec {
        "{",
        "    \"Fog domain\": \"fog.com\",",
        "    \"Agent ID\": \"fdfdf-5454-dfd\",",
        "    \"Fog port\": 443,",
        "    \"Encrypted connection\": false,",
        "    \"Tenant ID\": \"tenant_id\",",
        "    \"Profile ID\": \"profile\",",
        "    \"OpenSSL certificates directory\": \"\"",
        "}"
    };

    AgentDetails agent_details;
    agent_details.preload();

    CPTestTempfile agent_details_file(agent_details_vec);
    setConfiguration(agent_details_file.fname, "Agent details", "File path");

    EXPECT_FALSE(agent_details.getSSLFlag());
    EXPECT_THAT(agent_details.getOpenSSLDir(),  IsError("OpenSSL certificates directory was not set"));

    agent_details.setOpenSSLDir("a/b/c");
    EXPECT_THAT(agent_details.getOpenSSLDir(),  IsValue("a/b/c"));

    agent_details.setFogPort(10);
    agent_details.setSSLFlag(false);
    agent_details.setFogDomain("www.fog.checkpoint.com");
    agent_details.setOpenSSLDir("");

    EXPECT_THAT(agent_details.getFogPort(), IsValue(10));
    EXPECT_FALSE(agent_details.getSSLFlag());
    EXPECT_THAT(agent_details.getFogDomain(),   IsValue("www.fog.checkpoint.com"));
    EXPECT_THAT(agent_details.getOpenSSLDir(),  IsError("OpenSSL certificates directory was not set"));

    EXPECT_FALSE(agent_details.getOrchestrationMode() == OrchestrationMode::OFFLINE);
    agent_details.setOrchestrationMode(OrchestrationMode::OFFLINE);
    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::OFFLINE);
}

TEST_F(AgentDetailsTest, unrecognizedMachineType)
{
    env.preload();
    env.init();
    AgentDetails agent_details;
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput("dmidecode -s system-manufacturer | tr -d '\\n'", _, _)
    ).WillOnce(Return(string("Skynet")));
    agent_details.preload();
    agent_details.init();

    auto machine_type = Singleton::Consume<I_Environment>::from(env)->get<I_AgentDetails::MachineType>("MachineType");
    EXPECT_EQ(machine_type.unpack(), I_AgentDetails::MachineType::UNRECOGNIZED);
}
