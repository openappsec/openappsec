#include "agent_details.h"

#include <boost/regex.hpp>
#include <boost/algorithm/string.hpp>

#include "mock/mock_encryptor.h"
#include "mock/mock_shell_cmd.h"
#include "mock/mock_messaging.h"
#include "mock/mock_mainloop.h"
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
    StrictMock<MockMessaging> mock_messaging;
    StrictMock<MockEncryptor> mock_encryptor;
    StrictMock<MockShellCmd> mock_shell_cmd;
    Config::I_Config *config = nullptr;
    StrictMock<MockMainLoop> mock_ml;
};


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

    EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, "Load access token", _)).WillOnce(Return(0));

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
    agent_details.setRegisteredServer("server");
    EXPECT_EQ(agent_details.getFogDomain().unpack(), "fog.checkpoint.com");
    EXPECT_EQ(agent_details.getFogPort().unpack(), 80);
    EXPECT_EQ(agent_details.getAgentId(), "dfdfdf-dfd");
    EXPECT_EQ(agent_details.getRegisteredServer(), "server");
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
    EXPECT_EQ(agent_details.getRegisteredServer(), "server");

    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::OFFLINE);
    agent_details.setOrchestrationMode(OrchestrationMode::ONLINE);
    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::ONLINE);
    EXPECT_FALSE(agent_details.isOpenAppsecAgent());
    auto machine_type = Singleton::Consume<I_Environment>::from(env)->get<I_AgentDetails::MachineType>("MachineType");
    EXPECT_EQ(machine_type.unpack(), I_AgentDetails::MachineType::AZURE);
}

TEST_F(AgentDetailsTest, isOpenAppsecTest)
{
    const vector<string> agent_details_vec {
        "{",
        "    \"Fog domain\": \"fog.com\",",
        "    \"Agent ID\": \"fdfdf-5454-dfd\",",
        "    \"Fog port\": 443,",
        "    \"Encrypted connection\": false,",
        "    \"Orchestration mode\": \"offline_mode\",",
        "    \"Tenant ID\": \"org_123\",",
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
    EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, "Load access token", _)).WillOnce(Return(0));
    agent_details.init();
    auto i_conf = Singleton::Consume<Config::I_Config>::from(conf);
    i_conf->reloadConfiguration();
    CPTestTempfile agent_details_file(agent_details_vec);
    setConfiguration(agent_details_file.fname, "Agent details", "File path");

    EXPECT_TRUE(agent_details.readAgentDetails());

    EXPECT_EQ(agent_details.getTenantId(), "org_123");

    EXPECT_TRUE(agent_details.writeAgentDetails());

    EXPECT_TRUE(agent_details.readAgentDetails());

    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::OFFLINE);
    agent_details.setOrchestrationMode(OrchestrationMode::ONLINE);
    EXPECT_TRUE(agent_details.getOrchestrationMode() == OrchestrationMode::ONLINE);
    EXPECT_TRUE(agent_details.isOpenAppsecAgent());

    agent_details.setTenantId("tenant_id");
    EXPECT_FALSE(agent_details.isOpenAppsecAgent());
    agent_details.setOrchestrationMode(OrchestrationMode::HYBRID);
    EXPECT_TRUE(agent_details.isOpenAppsecAgent());
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
    EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, "Load access token", _)).WillOnce(Return(0));
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

class TestProxyConfiguration : public testing::Test
{
public:
    TestProxyConfiguration()
    :
        env_proxy_vars({
            {"http_proxy", ""},
            {"https_proxy", ""}
        }),
        i_proxy_config(Singleton::Consume<I_ProxyConfiguration>::from(agent_details))
    {
        for (auto &proxy_var: env_proxy_vars) {
            cleanEnvProxyVarFromEnv(proxy_var.first);
        }

        EXPECT_CALL(
            mock_shell_cmd,
            getExecOutput("dmidecode -s system-manufacturer | tr -d '\\n'", _, _)
        ).WillOnce(Return(string("Skynet")));

        EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, "Load access token", _)).WillOnce(Return(0));

        agent_details.init();
    }

    void
    cleanEnvProxyVarFromEnv(const string &proxy_var)
    {
        char *https_proxy = getenv(proxy_var.c_str());
        const char *upper_case_name = boost::algorithm::to_upper_copy(proxy_var).c_str();
        if (https_proxy == nullptr) {
            https_proxy = getenv(upper_case_name);
        }
        if (https_proxy) env_proxy_vars.at(proxy_var).assign(https_proxy);
        setenv(proxy_var.c_str(), "", 1);
        setenv(upper_case_name, "", 1);
    }

    ~TestProxyConfiguration()
    {
        for (auto &proxy_var: env_proxy_vars) {
            setenv(proxy_var.first.c_str(), proxy_var.second.c_str(), 1);
            setenv(boost::algorithm::to_upper_copy(proxy_var.first).c_str(), proxy_var.second.c_str(), 1);
        }
    }

    void
    setEnvironmentProxy(const map<ProxyProtocol, string> &proxy_config)
    {
        for (const auto &proxy_type : proxy_config) {
            switch(proxy_type.first) {
            case (ProxyProtocol::HTTPS): {
                setenv("http_proxy", proxy_type.second.c_str(), 1);
                break;
            }
            case (ProxyProtocol::HTTP): {
                setenv("https_proxy", proxy_type.second.c_str(), 1);
                break;
            }
            default:
                dbgAssert(false)
                    << AlertInfo(AlertTeam::CORE, "testing")
                    << "Unsupported ProxyProtocol "
                    << static_cast<int>(proxy_type.first);
            }
        }
    }

    map<string, string> env_proxy_vars;
    AgentDetails agent_details;
    I_ProxyConfiguration *i_proxy_config;
    StrictMock<MockEncryptor> mock_encryptor;
    StrictMock<MockShellCmd> mock_shell_cmd;
    StrictMock<MockMainLoop> mock_ml;
    ConfigComponent config;
    ::Environment env;

};

TEST_F(TestProxyConfiguration, load_policy)
{
    stringstream config;
    config << "{}";
    EXPECT_TRUE(Singleton::Consume<Config::I_Config>::from<ConfigComponent>()->loadConfiguration(config));
}

TEST_F(TestProxyConfiguration, ignore_proxy)
{
    string proxy_protocol = "http";
    string proxy_domain = "proxy.checkpoint.com";
    string proxy_port = "8080";
    string proxy_address = proxy_protocol + "://" + proxy_domain + ":" + proxy_port;

    setEnvironmentProxy(
        map<ProxyProtocol, string>(
            {
                {ProxyProtocol::HTTPS, proxy_address},
                {ProxyProtocol::HTTP, proxy_address}
            }
        )
    );

    EXPECT_THAT(
        i_proxy_config->getProxyAddress(ProxyProtocol::HTTP),
        IsError("Can't construct http proxy address")
    );
    EXPECT_THAT(
        i_proxy_config->getProxyAddress(ProxyProtocol::HTTPS),
        IsError("Can't construct https proxy address")
    );
    EXPECT_THAT(i_proxy_config->getProxyDomain(ProxyProtocol::HTTPS), IsError("https proxy domain is unset"));
    EXPECT_THAT(i_proxy_config->getProxyDomain(ProxyProtocol::HTTP), IsError("http proxy domain is unset"));
    EXPECT_THAT(i_proxy_config->getProxyPort(ProxyProtocol::HTTPS), IsError("https proxy port is unset"));
    EXPECT_THAT(i_proxy_config->getProxyPort(ProxyProtocol::HTTP), IsError("http proxy port is unset"));
    EXPECT_FALSE(i_proxy_config->getProxyExists(ProxyProtocol::HTTP));
    EXPECT_FALSE(i_proxy_config->getProxyExists(ProxyProtocol::HTTPS));
    EXPECT_FALSE(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).ok());
    EXPECT_FALSE(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).ok());
}

TEST_F(TestProxyConfiguration, basic_proxy)
{
    string proxy_protocol = "http";
    string proxy_domain = "proxy.checkpoint.com";
    string proxy_port = "8080";
    string proxy_address = proxy_protocol + "://" + proxy_domain + ":" + proxy_port;

    setEnvironmentProxy(
        map<ProxyProtocol, string>(
            {
                {ProxyProtocol::HTTPS, proxy_address},
                {ProxyProtocol::HTTP, proxy_address}
            }
        )
    );

    i_proxy_config->loadProxy();
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTP).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTPS).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTPS).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTP).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTPS).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTP).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTP), true);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTPS), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).ok(), false);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).ok(), false);
}

TEST_F(TestProxyConfiguration, proxy_authentication)
{
    string proxy_protocol = "http";
    string proxy_auth = "user:password";
    string proxy_domain = "proxy.checkpoint.com";
    string proxy_port = "8080";
    string proxy_address = proxy_protocol + "://" + proxy_domain + ":" + proxy_port;

    setEnvironmentProxy(
        map<ProxyProtocol, string>(
            {
                {ProxyProtocol::HTTPS, "http://user:password@proxy.checkpoint.com:8080"},
                {ProxyProtocol::HTTP, "http://user:password@proxy.checkpoint.com:8080"}
            }
        )
    );

    i_proxy_config->loadProxy();
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTP).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTPS).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTPS).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTP).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTPS).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTP).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTP), true);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTPS), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).unpack(), proxy_auth);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).unpack(), proxy_auth);
}

TEST_F(TestProxyConfiguration, proxy_protocol_addition)
{
    string proxy_protocol = "http";
    string proxy_auth = "user:password";
    string proxy_domain = "proxy.checkpoint.com";
    string proxy_port = "8080";
    string proxy_address = proxy_protocol + "://" + proxy_domain + ":" + proxy_port;

    setEnvironmentProxy(
        map<ProxyProtocol, string>(
            {
                {ProxyProtocol::HTTPS, "user:password@proxy.checkpoint.com:8080"},
                {ProxyProtocol::HTTP, "user:password@proxy.checkpoint.com:8080"}
            }
        )
    );

    i_proxy_config->loadProxy();
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTP).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTPS).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTPS).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTP).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTPS).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTP).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTP), true);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTPS), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).unpack(), proxy_auth);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).unpack(), proxy_auth);
}

TEST_F(TestProxyConfiguration, proxy_format_error)
{
    string proxy_protocol = "http";
    string proxy_auth = "user:password";
    string proxy_domain = "proxy.checkpoint.com";
    string proxy_port = "8080";
    string proxy_address = proxy_protocol + "://" + proxy_domain + ":" + proxy_port;

    setEnvironmentProxy(
        map<ProxyProtocol, string>(
            {
                {ProxyProtocol::HTTPS, "http://user:password@proxy.checkpoint.com:8080"},
                {ProxyProtocol::HTTP, "http://user:password@proxy.checkpoint.com:8080"}
            }
        )
    );

    i_proxy_config->loadProxy();
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTP).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyAddress(ProxyProtocol::HTTPS).unpack(), proxy_address);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTPS).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyDomain(ProxyProtocol::HTTP).unpack(), proxy_domain);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTPS).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyPort(ProxyProtocol::HTTP).unpack(), 8080);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTP), true);
    EXPECT_EQ(i_proxy_config->getProxyExists(ProxyProtocol::HTTPS), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).ok(), true);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTP).unpack(), proxy_auth);
    EXPECT_EQ(i_proxy_config->getProxyAuthentication(ProxyProtocol::HTTPS).unpack(), proxy_auth);
}
