#include <sstream>
class Package;
std::ostream & operator<<(std::ostream &os, const Package &) { return os; }

#include "orchestration_comp.h"

#include "cptest.h"
#include "mock/mock_encryptor.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_downloader.h"
#include "mock/mock_manifest_controller.h"
#include "mock/mock_service_controller.h"
#include "mock/mock_orchestration_status.h"
#include "mock/mock_update_communication.h"
#include "mock/mock_details_resolver.h"
#include "mock/mock_agent_details_reporter.h"
#include "mock/mock_logging.h"
#include "mock/mock_shell_cmd.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_tenant_manager.h"
#include "config.h"
#include "config_component.h"
#include "agent_details.h"
#include "customized_cereal_map.h"
#include "health_check_status/health_check_status.h"
#include "updates_process_event.h"
#include "declarative_policy_utils.h"
#include "mock/mock_env_details.h"

using namespace testing;
using namespace std;

string host_address = "1.2.3.5";
string host_url = "https://" + host_address + "/";
Maybe<string> response(
    string(
        "{\n"
        "    \"fog-address\": \"" + host_url + "\",\n"
        "    \"agent-type\": \"test\",\n"
        "    \"pulling-interval\": 25,\n"
        "    \"error-pulling-interval\": 15\n"
        "}"
    )
);
string orchestration_policy_file_path = "/etc/cp/conf/orchestration/orchestration.policy";
string orchestration_policy_file_path_bk = orchestration_policy_file_path + ".bk";

class ExpectInitializer
{
public:
    ExpectInitializer(StrictMock<MockOrchestrationTools> &mock_orchestration_tools)
    {
        EXPECT_CALL(mock_orchestration_tools, doesFileExist("/.dockerenv")).WillRepeatedly(Return(false));
    }
};

class OrchestrationTest : public testing::TestWithParam<bool>
{
public:
    OrchestrationTest()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::SET, "new-configuration", _))
            .WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::setNewConfiguration))
        );

        EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)).WillOnce(Return(0));
        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, _, _, _, _)
        ).WillRepeatedly(Return(0));

        config_comp.preload();
        config_comp.init();
    }

    void
    init()
    {
        EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_file_path)).WillOnce(Return(true));
        EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path)).WillOnce(Return(response));
        EXPECT_CALL(mock_status, setFogAddress(host_url)).WillRepeatedly(Return());
        EXPECT_CALL(mock_orchestration_tools, setClusterId());

        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(_, _, "Orchestration successfully updated (One-Time After Interval)", true)
        ).WillOnce(DoAll(SaveArg<1>(&upgrade_routine), Return(0)));

        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::System, _, "Orchestration runner", true)
        ).WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));

        EXPECT_CALL(
            mock_shell_cmd,
            getExecOutput("openssl version -d | cut -d\" \" -f2 | cut -d\"\\\"\" -f2", _, _)
        ).WillOnce(Return(string("OpenSSL certificates Directory")));

        EXPECT_CALL(mock_service_controller, isServiceInstalled("Access Control")).WillRepeatedly(
            InvokeWithoutArgs(
                []()
                {
                    static int count = 0;
                    if (count > 0) return false;
                    count++;
                    return true;
                }
            )
        );

        map<string, vector<PortNumber>> empty_service_to_port_map;
        EXPECT_CALL(mock_service_controller, getServiceToPortMap()).WillRepeatedly(Return(empty_service_to_port_map));

        EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "orchestration-status", _)).WillOnce(
            WithArg<2>(Invoke(this, &OrchestrationTest::setRestStatus))
        );

        EXPECT_CALL(
            rest,
            mockRestCall(RestAction::SET, "agent-uninstall", _)
        ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandlerAgentUninstall)));

        EXPECT_CALL(mock_message, sendAsyncMessage(
            HTTPMethod::POST,
            "/api/v1/agents/events",
            _,
            MessageCategory::LOG,
            _,
            _
        )).WillRepeatedly(SaveArg<2>(&message_body));

        doEncrypt();
        EXPECT_CALL(mock_orchestration_tools, loadTenantsFromDir(_)).Times(1);
        orchestration_comp.init();
    }

    bool
    restHandler(const unique_ptr<RestInit> &rest_ptr)
    {
        rest_handler = rest_ptr->getRest();
        return true;
    }

    bool
    restHandlerAgentUninstall(const unique_ptr<RestInit> &p)
    {
        agent_uninstall = p->getRest();
        return true;
    }

    void
    doEncrypt()
    {
        Maybe<string> err = genError("No file exist");
        EXPECT_CALL(mock_orchestration_tools, readFile("/etc/cp/conf/user-cred.json")).WillOnce(Return(err));

        EXPECT_CALL(mock_orchestration_tools, writeFile("This is fake", "/etc/cp/data/data1.a", false)).WillOnce(
            Return(true));
        EXPECT_CALL(mock_orchestration_tools, writeFile("0000 is fake", "/etc/cp/data/data4.a", false)).WillOnce(
            Return(true));
        EXPECT_CALL(mock_orchestration_tools, writeFile("This is 3333", "/etc/cp/data/data6.a", false)).WillOnce(
            Return(true));
    }

    void
    expectDetailsResolver()
    {
        Maybe<tuple<string, string, string, string>> no_nginx(genError("No nginx"));
        EXPECT_CALL(mock_details_resolver, getPlatform()).WillRepeatedly(Return(string("linux")));
        EXPECT_CALL(mock_details_resolver, getArch()).WillRepeatedly(Return(string("x86_64")));
        EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isCloudStorageEnabled()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isVersionAboveR8110()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillRepeatedly(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion()).WillRepeatedly(Return("1.1.1"));
        EXPECT_CALL(mock_details_resolver, getHostname()).WillRepeatedly(Return(string("hostname")));

        map<string, string> resolved_mgmt_details({{"kernel_version", "4.4.0-87-generic"}});
        EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillRepeatedly(Return(resolved_mgmt_details));
        EXPECT_CALL(mock_details_resolver, readCloudMetadata()).WillRepeatedly(
            Return(Maybe<tuple<string, string, string, string, string>>(genError("No cloud metadata")))
        );
    }

    string
    buildOrchestrationStatusJSON(
        const string &last_update_attempt = "None",
        const string &last_update_status = "None",
        const string &last_update = "None",
        const string &last_manifest_update = "None",
        const string &policy_version = "",
        const string &last_policy_update = "None",
        const string &last_settings_update = "None",
        const string &update_mode = "None",
        const string &fog_address = "None",
        const string &registration_status = "None",
        const string &manifest_status = "None",
        const string &registration_details_name = "",
        const string &registration_details_type = "",
        const string &registration_details_platform = "",
        const string &registration_details_architecture = "",
        const string &agent_id = "None",
        const string &profile_id = "None",
        const string &tenant_id = "None",
        const string &service_policy = "",
        const string &service_settings = ""
    )
    {
        string ans =    "{\n"
                        "    \"Last update attempt\": \"" + last_update_attempt + "\",\n"
                        "    \"Last update status\": \"" + last_update_status + "\",\n"
                        "    \"Last update\": \"" + last_update + "\",\n"
                        "    \"Last manifest update\": \"" + last_manifest_update + "\",\n"
                        "    \"Policy version\": \"" + policy_version + "\",\n"
                        "    \"Last policy update\": \"" + last_policy_update + "\",\n"
                        "    \"Last settings update\": \"" + last_settings_update + "\",\n"
                        "    \"Upgrade mode\": \"" + update_mode + "\",\n"
                        "    \"Fog address\": \"" + fog_address + "\",\n"
                        "    \"Registration status\": \"" + registration_status + "\",\n"
                        "    \"Registration details\": {\n"
                        "        \"Name\": \"" + registration_details_name + "\",\n"
                        "        \"Type\": \"" + registration_details_type + "\",\n"
                        "        \"Platform\": \"" + registration_details_platform + "\",\n"
                        "        \"Architecture\": \"" + registration_details_architecture + "\"\n"
                        "    },\n"
                        "    \"Agent ID\": \"" + agent_id + "\",\n"
                        "    \"Profile ID\": \"" + profile_id + "\",\n"
                        "    \"Tenant ID\": \"" + tenant_id + "\",\n"
                        "    \"Manifest status\": \"" + manifest_status + "\",\n"
                        "    \"Service policy\": {},\n"
                        "    \"Service settings\": {}\n"
                        "}";

        if (!service_policy.empty()) {
            string empty_policy = "    \"Service policy\": {},\n";
            ans.replace(
                ans.find(empty_policy),
                empty_policy.size(),
                "    \"Service policy\": {\n"
                "        " + service_policy + "\n"
                "    },\n"
            );
        }
        if (!service_settings.empty()) {
            string empty_settings = "    \"Service settings\": {}\n";
            ans.replace(
                ans.find(empty_settings),
                empty_settings.size(),
                "    \"Service settings\": {\n"
                "        " + service_settings + "\n"
                "    }\n"
            );
        }
        return ans;
    }

    void
    runRoutine()
    {
        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, "Send registration data", false)
        ).WillOnce(DoAll(SaveArg<1>(&sending_routine), Return(1)));

        routine();
    }

    void
    runRegTokenRoutine()
    {
        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::Offline, _, _, "Check For Environment Registration Token", _)
        ).WillOnce(DoAll(SaveArg<2>(&reg_token_routine), Return(0)));

        routine();
    }

    void
    runStatusRoutine()
    {
        status_routine();
    }

    void
    runUpgradeRoutine()
    {
        upgrade_routine();
    }

    void
    preload()
    {
        env.preload();
        orchestration_comp.preload();
    }

    string
    readFromFile(const string &path)
    {
        ifstream text_file(path);
        stringstream buffer;
        buffer << text_file.rdbuf();
        return buffer.str();
    }

    void
    waitForRestCall()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "orchestration-status", _)).WillRepeatedly(Return(true));
    }

    bool
    declareVariable(const unique_ptr<RestInit> &p)
    {
        set_new_configuration = p->getRest();
        return true;
    }

    unique_ptr<ServerRest> rest_handler;
    unique_ptr<ServerRest> agent_uninstall;
    unique_ptr<ServerRest> declare_variable;
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> mock_time_get;
    ::Environment env;
    string first_policy_version = "";
    ConfigComponent config_comp;
    StrictMock<MockEncryptor> mock_encryptor;
    NiceMock<MockLogging> mock_log;
    unique_ptr<ServerRest> set_new_configuration;
    unique_ptr<ServerRest> rest_status;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    StrictMock<MockDownloader> mock_downloader;
    StrictMock<MockShellCmd> mock_shell_cmd;
    StrictMock<EnvDetailsMocker> mock_env_details;
    StrictMock<MockMessaging> mock_message;
    StrictMock<MockRestApi> rest;
    StrictMock<MockServiceController> mock_service_controller;
    StrictMock<MockManifestController> mock_manifest_controller;
    StrictMock<MockUpdateCommunication> mock_update_communication;
    StrictMock<MockOrchestrationStatus> mock_status;
    StrictMock<MockDetailsResolver> mock_details_resolver;
    NiceMock<MockAgenetDetailsReporter> mock_agent_reporter;
    NiceMock<MockTenantManager> tenant_manager;
    ExpectInitializer initializer{mock_orchestration_tools};
    OrchestrationComp orchestration_comp;
    DeclarativePolicyUtils declarative_policy_utils;
    AgentDetails agent_details;
    I_MainLoop::Routine sending_routine;
    I_MainLoop::Routine reg_token_routine;
    string message_body;

private:
    bool
    setNewConfiguration(const unique_ptr<RestInit> &p)
    {
        set_new_configuration = p->getRest();
        return true;
    }

    bool setRestStatus(const unique_ptr<RestInit> &p)
    {
        rest_status = p->getRest();
        return true;
    }

    I_MainLoop::Routine routine;
    I_MainLoop::Routine status_routine;
    I_MainLoop::Routine upgrade_routine;
};


TEST_F(OrchestrationTest, hybridModeRegisterLocalAgentRoutine)
{
    EXPECT_CALL(rest, mockRestCall(_, _, _)).WillRepeatedly(Return(true));

    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(
        vector<string>{"--orchestration-mode=hybrid_mode"}
    );

    preload();
    env.init();
    init();

    EXPECT_CALL(mock_service_controller, updateServiceConfiguration(_, _, _, _, _, _))
        .WillOnce(Return(Maybe<void>()));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, _)).WillRepeatedly(Return(string()));
    EXPECT_CALL(mock_service_controller, getPolicyVersion()).WillRepeatedly(ReturnRef(first_policy_version));
    EXPECT_CALL(mock_shell_cmd, getExecOutput(_, _, _)).WillRepeatedly(Return(string()));
    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    expectDetailsResolver();
    EXPECT_CALL(mock_update_communication, getUpdate(_));
    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(_));

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));


    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(Return())
        .WillOnce(Invoke([] (chrono::microseconds) { throw invalid_argument("stop while loop"); }));

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, "Send registration data", false)
    ).WillOnce(Return(1));

    try {
        runRegTokenRoutine();
    } catch (const invalid_argument& e) {}

    EXPECT_CALL(mock_update_communication, registerLocalAgentToFog());
    reg_token_routine();
}

TEST_F(OrchestrationTest, testAgentUninstallRest)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));

    init();

    Report report;
    EXPECT_CALL(mock_log, sendLog(_)).WillRepeatedly(SaveArg<0>(&report));

    stringstream ss("{}");
    Maybe<string> maybe_res = agent_uninstall->performRestCall(ss);
    EXPECT_TRUE(maybe_res.ok());
    EXPECT_EQ(maybe_res.unpack(),
        "{\n"
        "    \"notify_uninstall_to_fog\": true\n"
        "}"
    );

    stringstream report_ss;
    {
        cereal::JSONOutputArchive ar(report_ss);
        report.serialize(ar);
    }

    string report_str = report_ss.str();
    EXPECT_THAT(report_str, HasSubstr("\"eventName\": \"Agent started uninstall process\""));
    EXPECT_THAT(report_str, HasSubstr("\"issuingEngine\": \"agentUninstallProvider\""));
}

TEST_F(OrchestrationTest, register_config)
{
    EXPECT_CALL(rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _))
        .WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::declareVariable)));

    preload();
    env.init();

    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"Backup file extension\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"1\"\n"
        "            }\n"
        "        ],\n"
        "        \"Service name\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"3\"\n"
        "            }\n"
        "        ],\n"
        "        \"Packages directory\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"5\"\n"
        "            }\n"
        "        ],\n"
        "        \"Manifest file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"7\"\n"
        "            }\n"
        "        ],\n"
        "        \"Settings file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"8\"\n"
        "            }\n"
        "        ],\n"
        "        \"Configuration path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"9\"\n"
        "            }\n"
        "        ],\n"
        "        \"Policy file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"10\"\n"
        "            }\n"
        "        ],\n"
        "        \"Configuration directory\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"11\"\n"
        "            }\n"
        "        ],\n"
        "        \"Default Check Point directory\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"12\"\n"
        "            }\n"
        "        ],\n"
        "        \"Configuration file extension\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"13\"\n"
        "            }\n"
        "        ],\n"
        "        \"Policy file extension\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"14\"\n"
        "            }\n"
        "        ],\n"
        "        \"Temp file extension\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"15\"\n"
        "            }\n"
        "        ],\n"
        "        \"Orchestration status path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"16\"\n"
        "            }\n"
        "        ],\n"
        "        \"Data file path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"17\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);
    EXPECT_THAT(getConfiguration<string>("orchestration", "Backup file extension"),         IsValue("1"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Service name"),                  IsValue("3"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Packages directory"),            IsValue("5"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Manifest file path"),            IsValue("7"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Settings file path"),            IsValue("8"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Configuration path"),            IsValue("9"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Policy file path"),              IsValue("10"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Configuration directory"),       IsValue("11"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Default Check Point directory"), IsValue("12"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Configuration file extension"),  IsValue("13"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Policy file extension"),         IsValue("14"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Temp file extension"),           IsValue("15"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Orchestration status path"),     IsValue("16"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Data file path"),                IsValue("17"));
    env.fini();
}

TEST_F(OrchestrationTest, registertion_data_config)
{
    EXPECT_CALL(rest, mockRestCall(RestAction::ADD, "declare-boolean-variable", _))
        .WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::declareVariable)));

    preload();
    env.init();

    string config_json =
        "{\n"
        "    \"email-address\": \"fake@example.com\",\n"
        "    \"registered-server\": \"NGINX Server\"\n"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);
    EXPECT_THAT(getSetting<string>("email-address"), IsValue("fake@example.com"));
    EXPECT_THAT(getSetting<string>("registered-server"), IsValue("NGINX Server"));
    env.fini();
}

TEST_F(OrchestrationTest, check_sending_registration_data)
{
    EXPECT_CALL(rest, mockRestCall(_, _, _)).WillRepeatedly(Return(true));

    preload();
    env.init();
    init();

    EXPECT_CALL(mock_env_details, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));

    EXPECT_CALL(mock_service_controller, updateServiceConfiguration(_, _, _, _, _, _))
        .WillOnce(Return(Maybe<void>()));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, _)).WillRepeatedly(Return(string()));
    EXPECT_CALL(mock_service_controller, getPolicyVersion()).WillRepeatedly(ReturnRef(first_policy_version));
    EXPECT_CALL(mock_shell_cmd, getExecOutput(_, _, _)).WillRepeatedly(Return(string()));
    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    expectDetailsResolver();
    EXPECT_CALL(mock_update_communication, getUpdate(_));
    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(_));

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));
    string config_json =
        "{\n"
        "    \"email-address\": \"fake@example.com\",\n"
        "    \"registered-server\": \"NGINX Server\"\n"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(Return())
        .WillOnce(Invoke([] (chrono::microseconds) { throw invalid_argument("stop while loop"); }));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}


    sending_routine();

    EXPECT_THAT(message_body, HasSubstr("\"userDefinedId\": \"fake@example.com\""));
    EXPECT_THAT(message_body, HasSubstr("\"eventCategory\""));

    EXPECT_THAT(message_body, AnyOf(HasSubstr("\"Embedded Deployment\""), HasSubstr("\"Kubernetes Deployment\"")));
    EXPECT_THAT(message_body, HasSubstr("\"NGINX Server\""));
}

TEST_F(OrchestrationTest, orchestrationPolicyUpdatRollback)
{
    Debug::setUnitTestFlag(D_CONFIG, Debug::DebugLevel::TRACE);
    waitForRestCall();
    preload();

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, "Send policy update report", _)
    ).WillOnce(Return(1));
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));

    string config_json =
        "{\n"
        "\"agentSettings\": [{\n"
                "\"key\": \"agent.config.orchestration.reportAgentDetail\",\n"
                "\"id\": \"id1\",\n"
                "\"value\": \"true\"\n"
            "}]\n"
        "}\n";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);

    init();

    // All duplicates should be removed in INXT-35947
    string orchestration_policy_file_path = "/etc/cp/conf/orchestration/orchestration.policy";
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string policy_file_path_bk = "/etc/cp/conf/policy.json.bk";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";
    string host_address = "1.2.3.5";
    string new_host_address = "6.2.3.5";
    string new_host_url = "https://" + new_host_address + "/test/";
    string new_policy_path = "/some-path";

    string manifest_checksum = "manifest";
    string policy_checksum = "policy";
    string settings_checksum = "settings";
    string data_checksum = "data";
    string new_policy_checksum= "111111";

    string second_val = "12";
    string third_val = "13";

    Maybe<string> new_policy_response(
        string(
            "{\n"
            "    \"fog-address\": \"" + new_host_url + "\",\n"
            "    \"agent-type\": \"test\",\n"
            "    \"pulling-interval\": 25,\n"
            "    \"error-pulling-interval\": 15\n"
            "}"
        )
    );

    set<string> expected_changed_policies = {};
    EXPECT_CALL(mock_service_controller, mockMoveChangedPolicies()).WillOnce(Return(expected_changed_policies));

    EXPECT_CALL(mock_status, setFogAddress(new_host_url));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_file_path))
        .WillOnce(Return(true))
        .WillOnce(Return(true));
    // Rollback related test: The readFile function is called 3 times:
    // 1. Read the current policy file
    // 2. Read the new policy file - The one that should fail
    // 3. Read the current policy file again - The one that should be restored
    EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path))
        .WillOnce(Return(new_policy_response))
        .WillOnce(Return(response));
    EXPECT_CALL(mock_orchestration_tools, copyFile(new_policy_path, policy_file_path + ".last"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_message, setFogConnection(host_address, 443, true, MessageCategory::GENERIC))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_update_communication, setAddressExtenesion(""));
    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    // Rollback related test: After failing to update the policy file, the policy version should be restored
    EXPECT_CALL(mock_service_controller, getPolicyVersion())
        .Times(6)
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(second_val))
        .WillOnce(ReturnRef(third_val))
        .WillOnce(ReturnRef(second_val)
    );
    EXPECT_CALL(mock_status, setPolicyVersion(third_val));
    EXPECT_CALL(mock_status, setPolicyVersion(second_val));

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    string policy_versions;
    EXPECT_CALL(mock_service_controller, getPolicyVersions()).WillRepeatedly(ReturnRef(policy_versions));
    EXPECT_CALL(mock_update_communication, sendPolicyVersion("13", _)).Times(1).WillOnce(Return(Maybe<void>()));
    // Rollback related test: The old policy version 12 is restored
    EXPECT_CALL(mock_update_communication, sendPolicyVersion("12", _)).Times(1).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                EXPECT_THAT(req.getData(), IsValue(data_checksum));
                req = CheckUpdateRequest("", new_policy_checksum, "", "", "", "");
                return Maybe<void>();
            }
        )
    );

    GetResourceFile policy_file(GetResourceFile::ResourceFileType::POLICY);
    EXPECT_CALL(
        mock_downloader,
        downloadFile(new_policy_checksum, Package::ChecksumTypes::SHA256, policy_file)
    ).WillOnce(Return(Maybe<std::string>(new_policy_path)));

    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(new_policy_path, "", expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_message,
        setFogConnection(new_host_address, 443, true, MessageCategory::GENERIC)
    ).WillOnce(Return(true));
    EXPECT_CALL(mock_update_communication, setAddressExtenesion("/test"));
    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
            }
        )
    );

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(25000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));

    EXPECT_CALL(mock_service_controller, clearFailedServices());
    EXPECT_CALL(mock_service_controller, doesFailedServicesExist()).WillOnce(Return(true));
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path_bk, _, _, _, _, _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(policy_file_path_bk, policy_file_path)
    ).WillOnce(Return(true));


    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
}

TEST_F(OrchestrationTest, orchestrationPolicyUpdate)
{
    waitForRestCall();
    preload();

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, "Send policy update report", _)
    ).WillOnce(Return(1));
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));

    init();

    string orchestration_policy_file_path = "/etc/cp/conf/orchestration/orchestration.policy";
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";
    string host_address = "1.2.3.5";
    string new_host_address = "6.2.3.5";
    string new_host_url = "https://" + new_host_address + "/test/";
    string new_policy_path = "/some-path";

    string manifest_checksum = "manifest";
    string policy_checksum = "policy";
    string settings_checksum = "settings";
    string data_checksum = "data";
    string new_policy_checksum= "111111";

    string second_val = "12";
    string third_val = "13";

    Maybe<string> new_policy_response(
        string(
            "{\n"
            "    \"fog-address\": \"" + new_host_url + "\",\n"
            "    \"agent-type\": \"test\",\n"
            "    \"pulling-interval\": 25,\n"
            "    \"error-pulling-interval\": 15\n"
            "}"
        )
    );

    set<string> expected_changed_policies = {};
    EXPECT_CALL(mock_service_controller, mockMoveChangedPolicies()).WillOnce(Return(expected_changed_policies));

    EXPECT_CALL(mock_status, setFogAddress(new_host_url));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path))
        .WillOnce(Return(new_policy_response));
    EXPECT_CALL(mock_orchestration_tools, copyFile(new_policy_path, policy_file_path + ".last"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    EXPECT_CALL(mock_service_controller, getPolicyVersion())
        .Times(5)
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(second_val))
        .WillOnce(ReturnRef(third_val)
    );
    EXPECT_CALL(mock_status, setPolicyVersion(third_val));

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    string policy_versions;
    EXPECT_CALL(mock_service_controller, getPolicyVersions()).WillRepeatedly(ReturnRef(policy_versions));
    EXPECT_CALL(mock_update_communication, sendPolicyVersion("13", _)).Times(1).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                EXPECT_THAT(req.getData(), IsValue(data_checksum));
                req = CheckUpdateRequest("", new_policy_checksum, "", "", "", "");
                return Maybe<void>();
            }
        )
    );

    GetResourceFile policy_file(GetResourceFile::ResourceFileType::POLICY);
    EXPECT_CALL(
        mock_downloader,
        downloadFile(new_policy_checksum, Package::ChecksumTypes::SHA256, policy_file)
    ).WillOnce(Return(Maybe<std::string>(new_policy_path)));

    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(new_policy_path, "", expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_message,
        setFogConnection(new_host_address, 443, true, MessageCategory::GENERIC)
    ).WillOnce(Return(true));
    EXPECT_CALL(mock_update_communication, setAddressExtenesion("/test"));
    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
            }
        )
    );

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(25000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
}

TEST_F(OrchestrationTest, loadOrchestrationPolicyFromBackup)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    );
    waitForRestCall();

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(_, _, "Orchestration successfully updated (One-Time After Interval)", true)
    );

    EXPECT_CALL(
        mock_ml,
        addOneTimeRoutine(I_MainLoop::RoutineType::System, _, "Orchestration runner", true)
    );

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput("openssl version -d | cut -d\" \" -f2 | cut -d\"\\\"\" -f2", _, _)
    ).WillOnce(Return(string("OpenSSL certificates Directory")));

    EXPECT_CALL(mock_service_controller, isServiceInstalled("Access Control")).WillRepeatedly(
        InvokeWithoutArgs(
            []()
            {
                static int count = 0;
                if (count > 0) return false;
                count++;
                return true;
            }
        )
    );

    map<string, vector<PortNumber>> empty_service_to_port_map;
    EXPECT_CALL(mock_service_controller, getServiceToPortMap()).WillRepeatedly(Return(empty_service_to_port_map));

    EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "orchestration-status", _));

    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::SET, "agent-uninstall", _)
    );

    doEncrypt();
    EXPECT_CALL(mock_orchestration_tools, loadTenantsFromDir(_)).Times(1);

    EXPECT_CALL(mock_status, setFogAddress(host_url));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, setClusterId());
    EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path))
        .WillOnce(Return(Maybe<string>(genError("Failed"))));
    EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path_bk)).WillOnce(Return(response));
    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(orchestration_policy_file_path_bk, orchestration_policy_file_path)
    ).WillOnce(Return(true));

    orchestration_comp.init();
}

TEST_F(OrchestrationTest, newServicePolicyUpdate)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
}

TEST_F(OrchestrationTest, manifestUpdate)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";

    string host_address = "1.2.3.5";
    string manifest_checksum= "manifest";
    string policy_checksum= "policy";
    string settings_checksum= "settings";
    string data_checksum = "data";

    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    EXPECT_CALL(mock_service_controller, getPolicyVersion())
        .Times(3).WillRepeatedly(ReturnRef(first_policy_version));
    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                EXPECT_THAT(req.getData(), IsValue(data_checksum));
                req = CheckUpdateRequest("new check sum", "", "", "", "", "");
                return Maybe<void>();
            }
        )
    );

    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
            }
        )
    );

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    GetResourceFile manifest_file(GetResourceFile::ResourceFileType::MANIFEST);
    EXPECT_CALL(mock_downloader,
        downloadFile(
            string("new check sum"),
            Package::ChecksumTypes::SHA256,
            manifest_file
        )
    ).WillOnce(Return(Maybe<std::string>(string("manifest path"))));
    EXPECT_CALL(mock_manifest_controller, updateManifest(string("manifest path"))).WillOnce(Return(true));
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(25000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}

    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/revert/upgrade_status")).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/revert/last_known_working_orchestrator"))
        .WillOnce(Return(true));

    Maybe<string> upgrade_status(string("1.1.1 1.1.2 2025-01-28 07:53:23"));
    EXPECT_CALL(mock_orchestration_tools, readFile("/etc/cp/revert/upgrade_status"))
        .WillOnce(Return(upgrade_status));
    EXPECT_CALL(mock_orchestration_tools, removeFile("/etc/cp/revert/upgrade_status")).WillOnce(Return(true));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist("/etc/cp/revert/failed_upgrade_info"))
        .WillOnce(Return(false));

    EXPECT_CALL(mock_details_resolver, getAgentVersion()).WillRepeatedly(Return("1.1.2"));
    EXPECT_CALL(mock_orchestration_tools, copyFile(_, "/etc/cp/revert/last_known_working_orchestrator"))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(_, "/etc/cp/revert/last_known_manifest")).WillOnce(Return(true));
    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile("1.1.1 1.1.2 2025-01-28 07:53:23\n", "/var/log/nano_agent/prev_upgrades", true)
    ).WillOnce(Return(true));
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(Return());
    runUpgradeRoutine();
}

TEST_F(OrchestrationTest, getBadPolicyUpdate)
{
    Debug::setUnitTestFlag(D_UPDATES_PROCESS_REPORTER, Debug::DebugLevel::NOISE);

    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";
    string new_policy_path = "policy path";

    string manifest_checksum = "manifest";
    string policy_checksum = "policy";
    string settings_checksum = "settings";
    string data_checksum = "data";

    vector<string> expected_data_types = {};

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).Times(2).WillRepeatedly(Return(Maybe<void>()));

    set<string> expected_changed_policies = {};
    EXPECT_CALL(mock_service_controller, mockMoveChangedPolicies()).WillOnce(Return(expected_changed_policies));

    EXPECT_CALL(mock_orchestration_tools, copyFile(new_policy_path, policy_file_path + ".last"))
        .WillOnce(Return(true));

    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    string manifest = "";
    string policy = "111111";
    string setting = "";

    string second_val = "12";
    string third_val = "13";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillRepeatedly(ReturnRef(third_val));
    Maybe<string> new_policy_checksum(string("111111"));

    GetResourceFile policy_file(GetResourceFile::ResourceFileType::POLICY);
    EXPECT_CALL(
        mock_downloader,
            downloadFile(
            string("111111"),
            Package::ChecksumTypes::SHA256,
            policy_file
        )
    ).WillOnce(Return(Maybe<std::string>(string(new_policy_path))));
    EXPECT_CALL(mock_service_controller, getPolicyVersion())
        .Times(4)
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(first_policy_version))
        .WillOnce(ReturnRef(second_val)
    );
    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
            }
        )
    );

    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                req = CheckUpdateRequest(manifest, policy, setting, "", "", "");
                return Maybe<void>();
            }
        )
    );

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(string("policy path"), "", expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>(genError(string("Fail to load policy")))));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(15000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
}

TEST_F(OrchestrationTest, failedDownloadSettings)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";

    string host_address = "1.2.3.5";
    string manifest_checksum = "manifest-checksum";
    string policy_checksum = "policy-checksum";
    string settings_checksum = "settings-checksum";
    string data_checksum = "data";

    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();

    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    Maybe<string> new_policy_checksum(string("111111"));

    EXPECT_CALL(mock_service_controller, getPolicyVersion())
        .Times(3).WillRepeatedly(ReturnRef(first_policy_version));
    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                req = CheckUpdateRequest(manifest_checksum, policy_checksum, settings_checksum, "", "", "");
                return Maybe<void>();
            }
        )
    );

    EXPECT_CALL(mock_status, setLastUpdateAttempt());

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    string manifest_err =
        "Critical Error: Agent/Gateway was not fully deployed on host 'hostname' "
        "and is not enforcing a security policy. Retry installation or contact Check Point support.";
    EXPECT_CALL(mock_status, getManifestError()).WillOnce(ReturnRef(manifest_err));

    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   true);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], true);
            }
        )
    );
    Maybe<string> download_error = genError("Failed to download");
    GetResourceFile settings_file(GetResourceFile::ResourceFileType::SETTINGS);
    GetResourceFile policy_file(GetResourceFile::ResourceFileType::POLICY);
    GetResourceFile manifest_file(GetResourceFile::ResourceFileType::MANIFEST);

    EXPECT_CALL(mock_downloader,
            downloadFile(
            string("manifest-checksum"),
            Package::ChecksumTypes::SHA256,
            manifest_file
        )
    ).WillOnce(Return(download_error));
    EXPECT_CALL(mock_downloader,
            downloadFile(
            string("settings-checksum"),
            Package::ChecksumTypes::SHA256,
            settings_file
        )
    ).WillOnce(Return(download_error));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(15000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
}

TEST_P(OrchestrationTest, orchestrationFirstRun)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";

    string host_address = "1.2.3.5";
    string manifest_checksum = "manifest";
    string policy_checksum = "policy";
    string settings_checksum = "settings";
    string data_checksum = "data";

    string manifest = "";
    string policy = "";
    string setting = "";

    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    expectDetailsResolver();
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::DATA],     false);
            }
        )
    );

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    EXPECT_CALL(mock_service_controller, getPolicyVersion()).WillRepeatedly(ReturnRef(first_policy_version));
    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                req = CheckUpdateRequest(manifest, policy, setting, "", "", "");
                return Maybe<void>();
            }
        )
    );
    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(25000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_status, writeStatusToFile());

    orchestration_comp.fini();
}

INSTANTIATE_TEST_CASE_P(getBadPolicyUpdate, OrchestrationTest, ::testing::Values(false, true));

TEST_F(OrchestrationTest, GetRestOrchStatus)
{
    string test_str = "Test";
    string agent_details =
        "    Name: name"
        "    Type: test_type"
        "    Platform: platform"
        "    Architecture: arch";
    string ans =    "{\n"
                    "    \"Last update attempt\": \"" + test_str + "\",\n"
                    "    \"Last update\": \"" + test_str + "\",\n"
                    "    \"Last update status\": \"" + test_str + "\",\n"
                    "    \"Policy version\": \"" + test_str + "\",\n"
                    "    \"Last policy update\": \"" + test_str + "\",\n"
                    "    \"Last manifest update\": \"" + test_str + "\",\n"
                    "    \"Last settings update\": \"" + test_str + "\",\n"
                    "    \"Registration status\": \"" + test_str + "\",\n"
                    "    \"Manifest status\": \"" + test_str + "\",\n"
                    "    \"Upgrade mode\": \"" + test_str + "\",\n"
                    "    \"Fog address\": \"" + test_str + "\",\n"
                    "    \"Agent ID\": \"" + test_str + "\",\n"
                    "    \"Profile ID\": \"" + test_str + "\",\n"
                    "    \"Tenant ID\": \"" + test_str + "\",\n"
                    "    \"Registration details\": \"" + agent_details +"\",\n"
                    "    \"Service policy\": \"\\n    service_a: path\",\n"
                    "    \"Service settings\": \"\\n    service_b: path\"\n"
                    "}";

    map<string, string> service_map_a = {{"service_a", "path"}};
    map<string, string> service_map_b = {{"service_b", "path"}};
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    EXPECT_CALL(mock_status, getLastUpdateAttempt()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getUpdateStatus()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getUpdateTime()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getLastManifestUpdate()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getPolicyVersion()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getLastPolicyUpdate()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getLastSettingsUpdate()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getUpgradeMode()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getFogAddress()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getRegistrationStatus()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getAgentId()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getProfileId()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getTenantId()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getManifestStatus()).WillOnce(ReturnRef(test_str));
    EXPECT_CALL(mock_status, getServicePolicies()).WillOnce(ReturnRef(service_map_a));
    EXPECT_CALL(mock_status, getServiceSettings()).WillOnce(ReturnRef(service_map_b));
    EXPECT_CALL(mock_status, getRegistrationDetails()).WillOnce(Return(agent_details));
    init();
    stringstream ss("{}");
    auto output = rest_status->performRestCall(ss);
    EXPECT_EQ(output.ok(), true);
    EXPECT_EQ(output.unpack(), ans);
}

TEST_F(OrchestrationTest, set_proxy)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();
    stringstream is;
    string proxy_url = "http://some-proxy.com:8080";
    is << "{\"proxy\": \""+ proxy_url +"\"}";
    rest_handler->performRestCall(is);
    auto maybe_proxy = agent_details.getProxy();
    EXPECT_TRUE(maybe_proxy.ok());
    EXPECT_EQ(maybe_proxy.unpack(), proxy_url);
}

TEST_F(OrchestrationTest, dataUpdate)
{
    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationTest::restHandler)));
    waitForRestCall();
    init();

    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";

    string host_address = "1.2.3.5";
    string manifest_checksum= "manifest";
    string policy_checksum= "policy";
    string settings_checksum= "settings";
    string data_checksum = "data";

    string data_download_path = "https://a/data.json";
    string data_checksum_type = "sha1sum";
    string data_instance_checksum = "8d4a5709673a05b380ba7d6567e28910019118f5";

    Maybe<string> data_response(
        string(
            "{\n"
            "    \"ips\": {\n"
            "       \"version\": \"c\",\n"
            "       \"downloadPath\": \"" + data_download_path + "\",\n"
            "       \"checksumType\": \"" + data_checksum_type + "\",\n"
            "       \"checksum\": \"" + data_instance_checksum + "\"\n"
            "    }\n"
            "}\n"
        )
    );

    vector<string> expected_empty_data_types = {};
    ExpectationSet expectation_set = EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(policy_file_path, setting_file_path, expected_empty_data_types, "", "", _)
    ).WillOnce(Return(Maybe<void>()));

    vector<string> expected_ips_data_types = { "ips" };
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration("", "", expected_ips_data_types, "", "", _)
    ).After(expectation_set).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(mock_orchestration_tools, doesDirectoryExist("/etc/cp/conf/data")).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(data_file_path + ".download")).WillOnce(Return(data_response));

    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
    EXPECT_CALL(mock_manifest_controller, loadAfterSelfUpdate()).WillOnce(Return(false));
    expectDetailsResolver();
    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, manifest_file_path))
        .WillOnce(Return(manifest_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, setting_file_path))
        .WillOnce(Return(settings_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, policy_file_path))
        .WillOnce(Return(policy_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, data_file_path))
        .WillOnce(Return(data_checksum));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(Package::ChecksumTypes::SHA256, "/path/ips"))
        .WillOnce(Return(data_instance_checksum));

    EXPECT_CALL(mock_service_controller, getPolicyVersion()).WillRepeatedly(ReturnRef(first_policy_version));

    string version = "1";
    EXPECT_CALL(mock_service_controller, getUpdatePolicyVersion()).WillOnce(ReturnRef(version));

    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                EXPECT_THAT(req.getData(), IsValue(data_checksum));
                req = CheckUpdateRequest("", "", "", "new data", "", "");
                return Maybe<void>();
            }
        )
    );

    EXPECT_CALL(mock_status, setLastUpdateAttempt());
    EXPECT_CALL(mock_status, setIsConfigurationUpdated(A<EnumArray<OrchestrationStatusConfigType, bool>>())
    ).WillOnce(
        Invoke(
            [](EnumArray<OrchestrationStatusConfigType, bool> arr)
            {
                EXPECT_EQ(arr[OrchestrationStatusConfigType::MANIFEST], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::POLICY],   false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::SETTINGS], false);
                EXPECT_EQ(arr[OrchestrationStatusConfigType::DATA],     true);
            }
        )
    );

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(1000000, microseconds.count());
                }
            )
        )
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(25000000, microseconds.count());
                    throw invalid_argument("stop while loop");
                }
            )
        );

    string new_data_file_path = data_file_path + ".download";
    GetResourceFile data_file(GetResourceFile::ResourceFileType::DATA);
    EXPECT_CALL(mock_downloader,
        downloadFile(
            string("new data"),
            Package::ChecksumTypes::SHA256,
            data_file
        )
    ).WillOnce(Return(Maybe<std::string>(string(new_data_file_path))));

    EXPECT_CALL(mock_downloader,
        downloadFileFromURL(
            data_download_path,
            data_instance_checksum,
            Package::ChecksumTypes::SHA256,
            "data_ips"
        )
    ).WillOnce(Return(Maybe<std::string>(string("/path/ips"))));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(new_data_file_path, data_file_path)
    );
    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile("/path/ips", "/etc/cp/conf/data/ips.data")
    );
    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(_, _, _)
    ).WillRepeatedly(Return(string("daniel\n1\n")));

    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
}
