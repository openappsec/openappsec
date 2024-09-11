#include <sstream>
class Package;
static std::ostream & operator<<(std::ostream &os, const Package &) { return os; }

#include "cptest.h"
#include <string>
#include "orchestration_tools.h"
#include <memory>
#include <map>
#include <thread>
#include "service_controller.h"
#include "config.h"
#include "config_component.h"
#include "declarative_policy_utils.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_orchestration_status.h"
#include "mock/mock_time_get.h"
#include "mock/mock_rest_api.h"
#include "mock/mock_messaging.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_logging.h"
#include "mock/mock_shell_cmd.h"
#include "mock/mock_tenant_manager.h"

using namespace testing;
using namespace std;

USE_DEBUG_FLAG(D_SERVICE_CONTROLLER);

class ServiceControllerTest : public Test
{
public:
    ServiceControllerTest()
    {
        registered_services_file_path = status_file.fname;
        setConfiguration(registered_services_file_path, "orchestration", "Orchestration registered services");

        EXPECT_CALL(time, getWalltimeStr(_)).WillRepeatedly(Return("time"));
        EXPECT_CALL(time, getMonotonicTime()).WillRepeatedly(Return(chrono::microseconds(1)));

        EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "nano-service-config", _)).WillOnce(
            WithArg<2>(Invoke(this, &ServiceControllerTest::setNanoServiceConfig))
        );

        EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "new-configuration", _)).WillOnce(
            WithArg<2>(Invoke(this, &ServiceControllerTest::setNanoServiceConfig))
        );

        EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)).WillOnce(Return(1));
        config.init();

        EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SHOW, "all-service-ports", _)).WillOnce(
            WithArg<2>(Invoke(this, &ServiceControllerTest::getServicesPorts))
        );

        EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "reconf-status", _)).WillOnce(
            WithArg<2>(Invoke(this, &ServiceControllerTest::setReconfStatus))
        );

        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(_, _, _, "Cleanup virtual tenants", _)
        ).WillOnce(DoAll(SaveArg<2>(&v_tenants_cleanup), Return(0)));

        Maybe<string> err = genError("Cannot read file, file does not exist");
        EXPECT_CALL(
            mock_orchestration_tools,
            readFile(registered_services_file_path)
        ).WillOnce(Return(err));

        configuration_dir = getConfigurationWithDefault<string>(
            "/etc/cp/conf",
            "orchestration",
            "Configuration directory"
        );
        policy_extension = getConfigurationWithDefault<string>(
            ".policy",
            "orchestration",
            "Configuration file extension"
        );
        settings_extension = getConfigurationWithDefault<string>(
            ".conf",
            "orchestration",
            "Configuration file extension"
        );
        backup_extension = getConfigurationWithDefault<string>(
            ".bk",
            "orchestration",
            "Backup file extension"
        );
        l4_firewall_policy_path = "/etc/cp/conf/l4_firewall/l4_firewall" + policy_extension;
        l4_firewall_settings_path = configuration_dir + "/l4_firewall/l4_firewall" + settings_extension;
        l4_firewall_debug_path = configuration_dir + "/l4_firewall/l4_firewall_debug" + settings_extension;
        file_name= "in_test.json";
        policy_file_path = getConfigurationWithDefault<string>(
            "/etc/cp/conf/policy.json",
            "orchestration",
            "Policy file path"
        );
        settings_file_path = getConfigurationWithDefault<string>(
            "/etc/cp/conf/settings.json",
            "orchestration",
            "Settings file path"
        );
    }

    void
    init()
    {
        service_controller.init();
        registerNewService();
    }

    bool setNanoServiceConfig(const unique_ptr<RestInit> &p) { set_nano_service_config = p->getRest(); return true; }
    bool getServicesPorts(const unique_ptr<RestInit> &p) { get_services_ports = p->getRest(); return true; }
    bool setReconfStatus(const unique_ptr<RestInit> &p) { set_reconf_status = p->getRest(); return true; }
    bool setNewConfiguration(const unique_ptr<RestInit> &p) { set_new_configuration = p->getRest(); return true; }

    ~ServiceControllerTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    string
    orchestrationRegisteredServicesFileToString(const string &file_name)
    {
        ifstream status_file(file_name);
        stringstream string_stream;
        if (status_file.is_open()) {
            string line;
            bool is_first_line = true;
            while (getline(status_file, line)) {
                if (is_first_line) {
                    is_first_line = false;
                } else {
                    string_stream << endl;
                }
                string_stream << line;
            }
            status_file.close();
        }
        return string_stream.str();
    }

    void
    registerNewService()
    {
        stringstream new_service_registration;
        new_service_registration
            << "{"
            << "    \"service_name\": \"mock access control\","
            << "    \"service_listening_port\":" + to_string(l4_firewall_service_port) + ","
            << "    \"expected_configurations\": [\"l4_firewall\", \"non updated capability\"],"
            << "    \"service_id\": \"family1_id2\","
            << "    \"general_settings\": \"path_to_settings\","
            << "    \"debug_settings\": \"path_to_debug\""
            << "}";

        auto registration_res = set_nano_service_config->performRestCall(new_service_registration);
        ASSERT_TRUE(registration_res.ok());

        i_service_controller = Singleton::Consume<I_ServiceController>::from(service_controller);
        EXPECT_TRUE(i_service_controller->isServiceInstalled("family1_id2"));
        EXPECT_FALSE(i_service_controller->isServiceInstalled("I am not installed"));

        string expected_json =  "{\n"
                                "    \"Registered Services\": {\n"
                                "        \"family1_id2\": {\n"
                                "            \"Service name\": \"mock access control\",\n"
                                "            \"Service ID\": \"family1_id2\",\n"
                                "            \"Service port\": " + to_string(l4_firewall_service_port) + ",\n"
                                "            \"Relevant configs\": [\n"
                                "                \"non updated capability\",\n"
                                "                \"l4_firewall\"\n"
                                "            ]\n"
                                "        }\n"
                                "    }\n"
                                "}";
        EXPECT_EQ(orchestrationRegisteredServicesFileToString(registered_services_file_path), expected_json);
    }

    void
    expectNewConfigRequest(const string &response)
    {
        Maybe<HTTPResponse, HTTPResponse> res = HTTPResponse(HTTPStatusCode::HTTP_OK, response);
        EXPECT_CALL(
            mock_message,
            sendSyncMessage(
                HTTPMethod::POST,
                "/set-new-configuration",
                _,
                _,
                _
            )
        ).WillOnce(DoAll(SaveArg<2>(&version_body), Return(res)));
    }

    CPTestTempfile                      status_file;
    const uint16_t                      l4_firewall_service_port = 8888;
    const uint16_t                      waap_service_port = 7777;
    ::Environment                       env;
    ConfigComponent                     config;
    DeclarativePolicyUtils              declarative_policy_utils;
    string version_body;
    string                              configuration_dir;
    string                              policy_extension;
    string                              settings_extension;
    string                              backup_extension;
    string                              l4_firewall_policy_path;
    string                              l4_firewall_settings_path;
    string                              l4_firewall_debug_path;
    string                              file_name;
    string                              registered_services_file_path;
    string                              policy_file_path;
    string                              settings_file_path;
    string                              services_port;
    StrictMock<MockTimeGet>             time;
    StrictMock<MockRestApi>             mock_rest_api;
    StrictMock<MockMessaging>           mock_message;
    StrictMock<MockMainLoop>            mock_ml;
    StrictMock<MockShellCmd>            mock_shell_cmd;
    StrictMock<MockOrchestrationStatus> mock_orchestration_status;
    StrictMock<MockOrchestrationTools>  mock_orchestration_tools;
    StrictMock<MockTenantManager>       tenant_manager;
    NiceMock<MockLogging>               mock_log;
    ServiceController                   service_controller;
    I_ServiceController                 *i_service_controller;
    unique_ptr<ServerRest>              set_nano_service_config;
    unique_ptr<ServerRest>              get_services_ports;
    unique_ptr<ServerRest>              set_reconf_status;
    unique_ptr<ServerRest>              set_new_configuration;
    I_MainLoop::Routine                 v_tenants_cleanup;
    ostringstream                       capture_debug;
    string                              version_value = "1.0.2";
    string                              old_version = "1.0.1";

    string versions =
            "[\n"
            "    {\n"
            "        \"id\": \"d8c3cc3c-f9df-83c8-f875-322dd8a0c161\",\n"
            "        \"name\": \"Linux Embedded Agents\",\n"
            "        \"version\": \"1.0.2\",\n"
            "        \"profileType\": \"Embedded\"\n"
            "    }\n"
            "]";
    string old_versions =
            "["
            "    {"
            "        \"id\": \"d8c3cc3c-f9df-83c8-f875-322dd8a0c161\","
            "        \"name\": \"Linux Embedded Agents\","
            "        \"version\": \"1.0.1\","
            "        \"profileType\": \"Embedded\""
            "    }"
            "]";

};

TEST_F(ServiceControllerTest, doNothing)
{
    init();
}

TEST_F(ServiceControllerTest, UpdateConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_EQ(i_service_controller->getPolicyVersions(), "");

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    string general_settings_path = "/my/settings/path";
    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";

    expectNewConfigRequest(reply_msg);

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getPolicyVersions(), versions);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);

    stringstream ver_ss;
    ver_ss
        << "{\n"
        << "    \"id\": 1,\n"
        << "    \"policy_version\": \"1.0.2,[\\n"
        << "    {\\n"
        << "        \\\"id\\\": \\\"d8c3cc3c-f9df-83c8-f875-322dd8a0c161\\\",\\n"
        << "        \\\"name\\\": \\\"Linux Embedded Agents\\\",\\n"
        << "        \\\"version\\\": \\\"1.0.2\\\",\\n"
        << "        \\\"profileType\\\": \\\"Embedded\\\"\\n"
        << "    }\\n"
        << "]\"\n}";
    EXPECT_EQ(
        version_body,
        ver_ss.str()
    );
}

TEST_F(ServiceControllerTest, supportVersions)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": " + versions +
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_EQ(i_service_controller->getPolicyVersions(), "");

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    string general_settings_path = "/my/settings/path";
    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";

    expectNewConfigRequest(reply_msg);

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getPolicyVersions(), versions);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, TimeOutUpdateConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).Times(4).WillRepeatedly(
        InvokeWithoutArgs(
            [&]() -> Maybe<string>
            {
                static int counter = 0;
                if (counter++ < 2) {
                    return genError("Reached timeout while executing shell command:");
                }

                return string("registered and running");
            }
        )
    );

    string general_settings_path = "/my/settings/path";
    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, readRegisteredServicesFromFile)
{
    init();
    uint16_t family1_id3_port = 1111;
    string registered_services_json =  "{\n"
                            "    \"Registered Services\": {\n"
                            "        \"family1_id3\": {\n"
                            "            \"Service name\": \"mock access control\",\n"
                            "            \"Service ID\": \"family1_id3\",\n"
                            "            \"Service port\": " + to_string(family1_id3_port) + ",\n"
                            "            \"Relevant configs\": [\n"
                            "                \"non updated capability\",\n"
                            "                \"l4_firewall\"\n"
                            "            ]\n"
                            "        }\n"
                            "    }\n"
                            "}";
    EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "nano-service-config", _)).WillOnce(
        WithArg<2>(Invoke(this, &ServiceControllerTest::setNanoServiceConfig))
    );

    EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "new-configuration", _)).WillOnce(
        WithArg<2>(Invoke(this, &ServiceControllerTest::setNanoServiceConfig))
    );

    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, false)).WillOnce(Return(1));
    config.init();

    EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SHOW, "all-service-ports", _)).WillOnce(
        WithArg<2>(Invoke(this, &ServiceControllerTest::getServicesPorts))
    );

    EXPECT_CALL(mock_rest_api, mockRestCall(RestAction::SET, "reconf-status", _)).WillOnce(
        WithArg<2>(Invoke(this, &ServiceControllerTest::setReconfStatus))
    );

    EXPECT_CALL(
        mock_ml,
        addRecurringRoutine(_, _, _, "Cleanup virtual tenants", _)
    ).WillOnce(DoAll(SaveArg<2>(&v_tenants_cleanup), Return(0)));

    EXPECT_CALL(
        mock_orchestration_tools,
        readFile(registered_services_file_path)
    ).WillOnce(Return(registered_services_json));

    service_controller.init();

    auto services_to_port_map = i_service_controller->getServiceToPortMap();
    vector<PortNumber> ports = {l4_firewall_service_port, family1_id3_port};
    EXPECT_EQ(services_to_port_map.find("mock access control")->second, ports);
}

TEST_F(ServiceControllerTest, noPolicyUpdate)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =    "{"
                            "    \"app\": \"netfilter\","
                            "    \"l4_firewall_rules\": ["
                            "        {"
                            "            \"name\": \"allow_statefull_conns\","
                            "            \"flags\": [\"established\"],"
                            "            \"action\": \"accept\""
                            "        },"
                            "        {"
                            "            \"name\": \"icmp drop\","
                            "            \"flags\": [\"log\"],"
                            "            \"services\": [{\"name\":\"icmp\"}],"
                            "            \"action\": \"drop\""
                            "        }"
                            "    ]"
                            "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(l4_firewall));
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, SettingsAndPolicyUpdateCombinations)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));
    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string general_settings_path = "/my/settings/path";
    string reply_msg1 = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg1);

    // both policy and settings now being updated
    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);

    // Only settings now being updated
    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(l4_firewall));
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    general_settings_path += "/new";

    string reply_msg2 = "{\"id\": 2, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg2);

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, backup)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    string old_configuration =  "{"
                                "   \"version\": \"" + old_version + "\""
                                "   \"versions\": \"" + old_versions + "\""
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"reject\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(old_configuration));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(l4_firewall_policy_path, l4_firewall_policy_path + backup_extension)
    ).WillOnce(Return(true));
    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(l4_firewall, l4_firewall_policy_path, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    EXPECT_CALL(mock_message, sendSyncMessage(_, "/set-new-configuration", _, _, _))
        .WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, reply_msg)));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, backup_file_doesnt_exist)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    string old_configuration =  "{"
                                "   \"version\": \"" + old_version + "\""
                                "   \"versions\": \"" + old_versions + "\""
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"reject\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(old_configuration));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(l4_firewall_policy_path, l4_firewall_policy_path + backup_extension)
    ).WillOnce(Return(true));
    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(l4_firewall, l4_firewall_policy_path, false)).WillOnce(Return(true)
    );

    // backup file doesn't exist so the copyFile function should be called 0 times
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension)).Times(0);

    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, backupAttempts)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    string old_configuration =  "{"
                                "   \"version\": \"" + old_version + "\""
                                "   \"versions\": \"" + old_versions + "\""
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"reject\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(old_configuration));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(l4_firewall_policy_path, l4_firewall_policy_path + backup_extension)
    ).WillOnce(Return(true));

    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(l4_firewall, l4_firewall_policy_path, false)).WillOnce(Return(true)
    );

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(false))
        .WillOnce(Return(false))
        .WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    EXPECT_CALL(mock_ml, yield(false)).Times(2);
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));
    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, MultiUpdateConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       },"
                                "   \"orchestration\":"
                                "       {"
                                "           \"fog-address\": \"http://10.0.0.18:81/control/\","
                                "           \"agent-type\": \"13324sadsd2\","
                                "           \"proxy\": \"\","
                                "           \"pulling-interval\": 10,"
                                "           \"error-pulling-interval\": 15"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "   \"app\": \"netfilter\","
                                "   \"l4_firewall_rules\": ["
                                "       {"
                                "           \"name\": \"allow_statefull_conns\","
                                "           \"flags\": [\"established\"],"
                                "           \"action\": \"accept\""
                                "       },"
                                "       {"
                                "           \"name\": \"icmp drop\","
                                "           \"flags\": [\"log\"],"
                                "           \"services\": [{\"name\":\"icmp\"}],"
                                "           \"action\": \"drop\""
                                "       }"
                                "   ]"
                                "}";

    string orchestration =      "{"
                                "   \"fog-address\": \"http://10.0.0.18:81/control/\","
                                "   \"agent-type\": \"13324sadsd2\","
                                "   \"proxy\": \"\","
                                "   \"pulling-interval\": 10,"
                                "   \"error-pulling-interval\": 15"
                                " }";

    Maybe<map<string, string>> json_parser_return = map<string, string>({
        {"version", version_value},
        {"l4_firewall", l4_firewall},
        {"orchestration", orchestration},
        {"versions", versions}
    });

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    string orchestration_policy_path =  configuration_dir + "/orchestration/orchestration" + policy_extension;
    string orchestration_settings_path = configuration_dir + "/orchestration/orchestration" + settings_extension;

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("orchestration", orchestration_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, writeFile(orchestration, orchestration_policy_path, false))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    set<string> changed_policies = {
        "/etc/cp/conf/l4_firewall/l4_firewall.policy",
        "/etc/cp/conf/orchestration/orchestration.policy",
        policy_versions_path
    };
    EXPECT_EQ(i_service_controller->moveChangedPolicies(), changed_policies);
}

class TestSendRequestToService : public ClientRest
{
public:
    C2S_PARAM(string, mock_rest_request_body_tag);
};

TEST_F(ServiceControllerTest, badJsonFile)
{
    init();
    Maybe<string> err = genError("Error");
    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).Times(1).WillRepeatedly(Return(err));
    EXPECT_FALSE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
}

TEST_F(ServiceControllerTest, emptyServices)
{
    init();
    Maybe<map<string, string>> json_parser_return = map<string, string>();
    string empty_string = "";
    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).Times(1).WillRepeatedly(Return(empty_string));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(empty_string, _, _)).Times(1).WillRepeatedly(
        Return(json_parser_return)
    );

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
}

TEST_F(ServiceControllerTest, failingWhileLoadingCurrentConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<string> err = genError("Error");

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(err));

    EXPECT_FALSE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
}

TEST_F(ServiceControllerTest, failingWhileCopyingCurrentConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =    "{"
                            "    \"app\": \"netfilter\","
                            "    \"l4_firewall_rules\": ["
                            "        {"
                            "            \"name\": \"allow_statefull_conns\","
                            "            \"flags\": [\"established\"],"
                            "            \"action\": \"accept\""
                            "        },"
                            "        {"
                            "            \"name\": \"icmp drop\","
                            "            \"flags\": [\"log\"],"
                            "            \"services\": [{\"name\":\"icmp\"}],"
                            "            \"action\": \"drop\""
                            "        }"
                            "    ]"
                            "}";

    string old_configuration =  "{"
                                "   \"version\": \"" + old_version + "\""
                                "   \"versions\": \"" + old_versions + "\""
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"reject\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).Times(1).WillRepeatedly(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _)).Times(1).WillRepeatedly(
        Return(json_parser_return)
    );
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(old_configuration));
    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(l4_firewall_policy_path, l4_firewall_policy_path + backup_extension)
    ).WillOnce(Return(false));

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
    EXPECT_FALSE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");
}

TEST_F(ServiceControllerTest, ErrorUpdateConfigurationRest)
{
    init();
    Debug::setUnitTestFlag(D_SERVICE_CONTROLLER, Debug::DebugLevel::NOISE);
    Debug::setNewDefaultStdout(&capture_debug);
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    EXPECT_CALL(time, getWalltime()).WillRepeatedly(Return(chrono::microseconds(0)));

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(
            l4_firewall,
            l4_firewall_policy_path,
            false)).WillOnce(Return(true));
    EXPECT_CALL(
        mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY)
    );

    EXPECT_EQ(i_service_controller->getPolicyVersion(), "");

    EXPECT_TRUE(i_service_controller->isServiceInstalled("family1_id2"));

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("not-registered")));
    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));

    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Service mock access control is inactive")
    );
    EXPECT_FALSE(i_service_controller->isServiceInstalled("family1_id2"));
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);
}

TEST_F(ServiceControllerTest, errorWhileWrtingNewConfiguration)
{
    init();
    string new_configuration =  "{"
                                "   \"version\": \"" + version_value + "\""
                                "   \"versions\": \"" + versions + "\""
                                "   \"l4_firewall\":"
                                "       {"
                                "           \"app\": \"netfilter\","
                                "           \"l4_firewall_rules\": ["
                                "               {"
                                "                   \"name\": \"allow_statefull_conns\","
                                "                   \"flags\": [\"established\"],"
                                "                   \"action\": \"accept\""
                                "               },"
                                "               {"
                                "                   \"name\": \"icmp drop\","
                                "                   \"flags\": [\"log\"],"
                                "                   \"services\": [{\"name\":\"icmp\"}],"
                                "                   \"action\": \"drop\""
                                "               }"
                                "           ]"
                                "       }"
                                "}";

    string l4_firewall =        "{"
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"accept\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    string old_configuration =  "{"
                                "   \"version\": \"" + old_version + "\""
                                "   \"versions\": \"" + old_versions + "\""
                                "    \"app\": \"netfilter\","
                                "    \"l4_firewall_rules\": ["
                                "        {"
                                "            \"name\": \"allow_statefull_conns\","
                                "            \"flags\": [\"established\"],"
                                "            \"action\": \"reject\""
                                "        },"
                                "        {"
                                "            \"name\": \"icmp drop\","
                                "            \"flags\": [\"log\"],"
                                "            \"services\": [{\"name\":\"icmp\"}],"
                                "            \"action\": \"drop\""
                                "        }"
                                "    ]"
                                "}";

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).Times(1).WillRepeatedly(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _)).Times(1).WillRepeatedly(
        Return(json_parser_return)
    );
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(l4_firewall_policy_path)).WillOnce(Return(old_configuration));
    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(l4_firewall_policy_path, l4_firewall_policy_path + backup_extension)
    ).WillOnce(Return(true));

    EXPECT_CALL(
        mock_orchestration_tools,
        writeFile(l4_firewall, l4_firewall_policy_path, false)).WillOnce(Return(false)
    );

    EXPECT_FALSE(i_service_controller->updateServiceConfiguration(file_name, "").ok());
}

TEST_F(ServiceControllerTest, testPortsRest)
{
    init();
    stringstream empty_json;
    empty_json << "{}";
    auto res = get_services_ports->performRestCall(empty_json);
    ASSERT_TRUE(res.ok());
    EXPECT_THAT(res.unpack(), HasSubstr("mock-access-control:8888;"));
}

TEST_F(ServiceControllerTest, testMultitenantConfFiles)
{
    setSetting<string>("VirtualNSaaS", "agentType");
    init();

    map<pair<string, string>, pair<string, string>> tenant_files_input = {
        {make_pair("", ""),
        make_pair("/etc/cp/conf/policy.json", "")},
        {make_pair("tenant1", "1234"),
        make_pair("/etc/cp/conf/tenant1_profile_1234_policy.json", "/etc/cp/conf/tenant1_profile_1234_settings.json")},
        {make_pair("tenant2", "1235"),
        make_pair("/etc/cp/conf/tenant2_profile_1235_policy.json", "")}
    };

    set<string> ids = {"family1_id2"};
    set<string> empty_ids;

    EXPECT_CALL(tenant_manager, getInstances("tenant1", "1234")).WillRepeatedly(Return(ids));
    EXPECT_CALL(tenant_manager, getInstances("tenant2", "1235")).WillRepeatedly(Return(empty_ids));

    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": true, \"error_message\": \"\"}";
    expectNewConfigRequest(reply_msg);

    for(auto entry : tenant_files_input) {
        auto tenant = entry.first.first;
        auto profile = entry.first.second;
        auto files = entry.second;
        string conf_file_name = files.first;
        string settings_file_name = files.second;

        string new_configuration =  "{"
                                    "   \"version\": \"" + version_value + "\""
                                    "   \"versions\": \"" + versions + "\""
                                    "   \"l4_firewall\":"
                                    "       {"
                                    "           \"app\": \"netfilter\","
                                    "           \"l4_firewall_rules\": ["
                                    "               {"
                                    "                   \"name\": \"allow_statefull_conns\","
                                    "                   \"flags\": [\"established\"],"
                                    "                   \"action\": \"accept\""
                                    "               },"
                                    "               {"
                                    "                   \"name\": \"icmp drop\","
                                    "                   \"flags\": [\"log\"],"
                                    "                   \"services\": [{\"name\":\"icmp\"}],"
                                    "                   \"action\": \"drop\""
                                    "               }"
                                    "           ]"
                                    "       }"
                                    "}";

        string l4_firewall =        "{"
                                    "    \"app\": \"netfilter\","
                                    "    \"l4_firewall_rules\": ["
                                    "        {"
                                    "            \"name\": \"allow_statefull_conns\","
                                    "            \"flags\": [\"established\"],"
                                    "            \"action\": \"accept\""
                                    "        },"
                                    "        {"
                                    "            \"name\": \"icmp drop\","
                                    "            \"flags\": [\"log\"],"
                                    "            \"services\": [{\"name\":\"icmp\"}],"
                                    "            \"action\": \"drop\""
                                    "        }"
                                    "    ]"
                                    "}";

        Maybe<map<string, string>> json_parser_return =
            map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});
        EXPECT_CALL(mock_orchestration_tools, readFile(conf_file_name)).WillOnce(Return(new_configuration));
        EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, tenant, profile))
            .WillOnce(Return(json_parser_return));
        if (!tenant.empty()) {
            string l4_firewall_policy_path_new =
                configuration_dir + "/tenant_" + tenant +
                "_profile_" + profile +"/l4_firewall/l4_firewall" + policy_extension;
            string policy_versions_path_new =
                configuration_dir + "/tenant_" + tenant +
                "_profile_" + profile +"/versions/versions" + policy_extension;

            EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path_new)).WillOnce(Return(false));
            EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path_new, false))
                .WillOnce(Return(true));
            EXPECT_CALL(mock_orchestration_status,
                setServiceConfiguration("versions", policy_versions_path_new, OrchestrationStatusConfigType::POLICY));

            EXPECT_CALL(
                mock_orchestration_tools,
                doesDirectoryExist(configuration_dir + "/tenant_" + tenant + "_profile_" + profile)
            ).WillOnce(Return(false)).WillOnce(Return(true));

            EXPECT_CALL(
                mock_orchestration_tools,
                createDirectory(configuration_dir + "/tenant_" + tenant + "_profile_" + profile)
            ).WillOnce(Return(true));

            EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path_new)).WillOnce(Return(false));

            EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path_new, false))
                .WillOnce(Return(true));

            string new_policy_file_path =
                "/etc/cp/conf/tenant_" + tenant + "_profile_" + profile + "/" + "policy.json";
            EXPECT_CALL(
                mock_orchestration_tools,
                copyFile(new_policy_file_path, new_policy_file_path + backup_extension)
            ).WillOnce(Return(true));
            EXPECT_CALL(mock_orchestration_tools, copyFile(conf_file_name, new_policy_file_path))
                .WillOnce(Return(true));
            EXPECT_CALL(mock_orchestration_tools, doesFileExist(new_policy_file_path)).WillOnce(Return(true));

            EXPECT_CALL(mock_orchestration_status, setServiceConfiguration(
                "l4_firewall", l4_firewall_policy_path_new, OrchestrationStatusConfigType::POLICY)
            );
        } else {
            EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
            EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false)).
                WillOnce(Return(true));
            EXPECT_CALL(
                mock_orchestration_status,
                setServiceConfiguration(
                    "l4_firewall",
                    l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY
                )
            );

            string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
            EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
            EXPECT_CALL(
                mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
            EXPECT_CALL(mock_orchestration_status,
                setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));
        }

        EXPECT_CALL(
            mock_shell_cmd,
            getExecOutput(
                "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
                " --family family1 --id id2",
                _,
                _
            )
        ).WillRepeatedly(Return(string("registered and running")));

        EXPECT_TRUE(
            i_service_controller->updateServiceConfiguration(
                conf_file_name,
                settings_file_name,
                {},
                tenant,
                profile,
                tenant.empty()
            ).ok()
        );
    }
}

TEST_F(ServiceControllerTest, cleanup_virtual_files)
{
    init();
    string agent_tenants_files =
        "111111\n"
        "222222\n"
        "333333\n";

    set<string> active_tenants = {
        "222222"
    };

    EXPECT_CALL(mock_shell_cmd, getExecOutput("ls /etc/cp/conf | grep 'tenant_*' | cut -d '_' -f 2", _, _))
        .WillOnce(Return(agent_tenants_files));

    EXPECT_CALL(tenant_manager, fetchActiveTenants()).WillOnce(Return(active_tenants));

    EXPECT_CALL(mock_orchestration_tools, removeFile("/etc/cp/conf/111111_settings.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, removeFile("/etc/cp/conf/333333_settings.json")).WillOnce(Return(true));

    v_tenants_cleanup();
}

TEST_F(ServiceControllerTest, test_delayed_reconf)
{
    init();
    string new_configuration =
        "{"
        "   \"version\": \"" + version_value + "\""
        "   \"versions\": " + versions +
        "   \"l4_firewall\":"
        "       {"
        "           \"app\": \"netfilter\","
        "           \"l4_firewall_rules\": ["
        "               {"
        "                   \"name\": \"allow_statefull_conns\","
        "                   \"flags\": [\"established\"],"
        "                   \"action\": \"accept\""
        "               },"
        "               {"
        "                   \"name\": \"icmp drop\","
        "                   \"flags\": [\"log\"],"
        "                   \"services\": [{\"name\":\"icmp\"}],"
        "                   \"action\": \"drop\""
        "               }"
        "           ]"
        "       }"
        "}";

    string l4_firewall =
        "{"
        "    \"app\": \"netfilter\","
        "    \"l4_firewall_rules\": ["
        "        {"
        "            \"name\": \"allow_statefull_conns\","
        "            \"flags\": [\"established\"],"
        "            \"action\": \"accept\""
        "        },"
        "        {"
        "            \"name\": \"icmp drop\","
        "            \"flags\": [\"log\"],"
        "            \"services\": [{\"name\":\"icmp\"}],"
        "            \"action\": \"drop\""
        "        }"
        "    ]"
        "}";

    setConfiguration(60, "orchestration", "Reconfiguration timeout seconds");

    Maybe<map<string, string>> json_parser_return =
        map<string, string>({{"l4_firewall", l4_firewall}, {"version", version_value}, {"versions", versions}});

    string policy_versions_path = "/etc/cp/conf/versions/versions.policy";
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_versions_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(versions, policy_versions_path, false)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("versions", policy_versions_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, readFile(file_name)).WillOnce(Return(new_configuration));
    EXPECT_CALL(mock_orchestration_tools, jsonObjectSplitter(new_configuration, _, _))
        .WillOnce(Return(json_parser_return));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(l4_firewall_policy_path)).WillOnce(Return(false));
    EXPECT_CALL(mock_orchestration_tools, writeFile(l4_firewall, l4_firewall_policy_path, false)).
        WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_status,
        setServiceConfiguration("l4_firewall", l4_firewall_policy_path, OrchestrationStatusConfigType::POLICY));

    EXPECT_CALL(mock_orchestration_tools, copyFile(policy_file_path, policy_file_path + backup_extension))
        .WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, copyFile(file_name, policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, doesFileExist(policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_ml, yield(false)).Times(AnyNumber());

    EXPECT_CALL(
        mock_shell_cmd,
        getExecOutput(
            "/etc/cp/watchdog/cp-nano-watchdog --status --verbose --service mock access control"
            " --family family1 --id id2",
            _,
            _
        )
    ).WillRepeatedly(Return(string("registered and running")));

    string general_settings_path = "/my/settings/path";
    string reply_msg = "{\"id\": 1, \"error\": false, \"finished\": false, \"error_message\": \"\"}";
    stringstream reconf_status;
    reconf_status
        << "{"
        << "    \"id\": 1,"
        << "    \"service_name\": \"max\","
        << "    \"finished\": true,"
        << "    \"error\": false,"
        << "    \"error_message\": \"\""
        << "}";

    expectNewConfigRequest(reply_msg);

    auto func = [&] (chrono::microseconds) { set_reconf_status->performRestCall(reconf_status); };
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(2000000))).WillOnce(Invoke(func));


    EXPECT_TRUE(i_service_controller->updateServiceConfiguration(file_name, general_settings_path).ok());
    EXPECT_EQ(i_service_controller->getPolicyVersion(), version_value);
    EXPECT_EQ(i_service_controller->getUpdatePolicyVersion(), version_value);
}
