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

using namespace testing;
using namespace std;

class OrchestrationMultitenancyTest : public Test
{
public:
    OrchestrationMultitenancyTest() : config(Singleton::Consume<Config::I_Config>::from(config_comp))
    {
        EXPECT_CALL(
            rest,
            mockRestCall(RestAction::SET, "new-configuration", _)
        ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationMultitenancyTest::setNewConfiguration)));

        EXPECT_CALL(
            mock_ml,
            addRecurringRoutine(I_MainLoop::RoutineType::System, _, _, _, _)
        ).WillRepeatedly(Return(0));
        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::System, _, "Configuration update registration", false)
        ).WillOnce(Return(0));
        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, "Send registration data", false)
        ).WillRepeatedly(Return(0));

        config_comp.preload();
        config_comp.init();
    }

    void
    init()
    {
        EXPECT_CALL(mock_service_controller, isServiceInstalled("Access Control")).WillRepeatedly(Return(false));

        // This Holding the Main Routine of the Orchestration.
        EXPECT_CALL(
            mock_ml,
            addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, "Orchestration runner", true)
        ).WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));

        EXPECT_CALL(mock_orchestration_tools, getClusterId());

        EXPECT_CALL(mock_shell_cmd, getExecOutput("openssl version -d | cut -d\" \" -f2 | cut -d\"\\\"\" -f2", _, _))
            .WillOnce(Return(string("OpenSSL certificates Directory")));

        EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "orchestration-status", _)).WillOnce(
            WithArg<2>(Invoke(this, &OrchestrationMultitenancyTest::setRestStatus)));

        EXPECT_CALL(
            rest,
            mockRestCall(RestAction::SET, "agent-uninstall", _)
        ).WillOnce(Return(true));

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
        Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
        EXPECT_CALL(mock_details_resolver, getPlatform()).WillRepeatedly(Return(string("linux")));
        EXPECT_CALL(mock_details_resolver, getArch()).WillRepeatedly(Return(string("x86_64")));
        EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillRepeatedly(Return(false));
        EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillRepeatedly(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion()).WillRepeatedly(Return("1.1.1"));

        map<string, string> resolved_mgmt_details({{"kernel_version", "4.4.0-87-generic"}});
        EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillRepeatedly(Return(resolved_mgmt_details));
    }

    void
    runRoutine()
    {
        routine();
    }

    void
    preload()
    {
        orchestration_comp.preload();
    }

    void
    waitForRestCall()
    {
        EXPECT_CALL(rest, mockRestCall(RestAction::SHOW, "orchestration-status", _)).WillRepeatedly(Return(true));
    }

    void
    performSetNewConfiguration(const string &file_path)
    {
        stringstream rest_call_parameters;
        rest_call_parameters
            << "{\"configuration_file_paths\": ["
            << (file_path == "" ? file_path : (string("\"") + file_path + string("\"")))
            << "] }";
        set_new_configuration->performRestCall(rest_call_parameters);
    }

    bool
    declareVariable(const unique_ptr<RestInit> &p)
    {
        set_new_configuration = p->getRest();
        return true;
    }

    ::Environment env;
    AgentDetails agent_details;
    ConfigComponent config_comp;
    Config::I_Config *config;

    unique_ptr<ServerRest> set_new_configuration;
    unique_ptr<ServerRest> rest_status;
    unique_ptr<ServerRest> rest_handler;
    unique_ptr<ServerRest> declare_variable;

    StrictMock<MockMainLoop> mock_ml;
    StrictMock<MockEncryptor> mock_encryptor;
    StrictMock<MockOrchestrationTools> mock_orchestration_tools;
    StrictMock<MockDownloader> mock_downloader;
    StrictMock<MockShellCmd> mock_shell_cmd;
    StrictMock<MockMessaging> mock_message;
    StrictMock<MockRestApi> rest;
    StrictMock<MockServiceController> mock_service_controller;
    StrictMock<MockManifestController> mock_manifest_controller;
    StrictMock<MockUpdateCommunication> mock_update_communication;
    StrictMock<MockTenantManager> tenant_manager;

    NiceMock<MockOrchestrationStatus> mock_status;
    NiceMock<MockTimeGet> mock_time_get;
    NiceMock<MockDetailsResolver> mock_details_resolver;
    NiceMock<MockAgenetDetailsReporter> mock_agent_reporter;
    NiceMock<MockLogging> mock_log;

    OrchestrationComp orchestration_comp;

private:
    bool
    setNewConfiguration(const unique_ptr<RestInit> &p)
    {
        set_new_configuration = p->getRest();
        return true;
    }

    bool
    setRestStatus(const unique_ptr<RestInit> &p)
    {
        rest_status = p->getRest();
        return true;
    }

    I_MainLoop::Routine routine;
    I_MainLoop::Routine status_routine;
};

TEST_F(OrchestrationMultitenancyTest, init)
{
}

TEST_F(OrchestrationMultitenancyTest, handle_virtual_resource)
{
    string orchestration_policy_file_path = "/etc/cp/conf/orchestration/orchestration.policy";
    string manifest_file_path = "/etc/cp/conf/manifest.json";
    string setting_file_path = "/etc/cp/conf/settings.json";
    string policy_file_path = "/etc/cp/conf/policy.json";
    string last_policy_file_path = "/etc/cp/conf/policy.json.last";
    string data_file_path = "/etc/cp/conf/data.json";

    string host_address = "1.2.3.5";
    string manifest_checksum= "manifest";
    string policy_checksum= "policy";
    string settings_checksum= "settings";
    string data_checksum= "data";

    string first_policy_version = "";
    string host_url = "https://" + host_address + "/";

    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_ORCHESTRATOR, Debug::DebugLevel::TRACE);

    EXPECT_CALL(
        rest,
        mockRestCall(RestAction::ADD, "proxy", _)
    ).WillOnce(WithArg<2>(Invoke(this, &OrchestrationMultitenancyTest::restHandler)));
    waitForRestCall();
    init();
    expectDetailsResolver();

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

    EXPECT_CALL(mock_orchestration_tools, doesFileExist(orchestration_policy_file_path)).WillOnce(Return(true));
    EXPECT_CALL(mock_orchestration_tools, readFile(orchestration_policy_file_path)).WillOnce(Return(response));
    EXPECT_CALL(mock_message, setActiveFog(host_address, 443, true, MessageTypeTag::GENERIC)).WillOnce(Return(true));
    EXPECT_CALL(mock_update_communication, setAddressExtenesion(""));
    EXPECT_CALL(mock_update_communication, authenticateAgent()).WillOnce(Return(Maybe<void>()));
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
        .Times(2).WillRepeatedly(ReturnRef(first_policy_version));

    set<string> active_tenants = { "1236", "1235" };
    map<string, set<string>> old_tenant_profile_set;
    set<string> old_profiles = { "123123" };
    old_tenant_profile_set["321321"] = old_profiles;
    EXPECT_CALL(tenant_manager, fetchActiveTenants()).WillOnce(Return(active_tenants));
    EXPECT_CALL(tenant_manager, fetchAndUpdateActiveTenantsAndProfiles(false))
        .WillOnce(Return(old_tenant_profile_set));
    EXPECT_CALL(tenant_manager, deactivateTenant("321321", "123123")).Times(1);

    EXPECT_CALL(tenant_manager, addActiveTenantAndProfile("1235", "2311"));
    EXPECT_CALL(tenant_manager, addActiveTenantAndProfile("1236", "2611"));

    set<string> first_tenant_profiles = { "2611" };
    set<string> second_tenant_profiles = { "2311"};
    EXPECT_CALL(
        tenant_manager,
        fetchProfileIds("1236")).WillRepeatedly(Return(first_tenant_profiles)
    );

    EXPECT_CALL(
        tenant_manager,
        fetchProfileIds("1235")).WillRepeatedly(Return(second_tenant_profiles)
    );

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, "/etc/cp/conf/tenant_1236_profile_2611/policy.json"))
        .WillOnce(Return(string("checksum_policy_tenant_1236")));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, "/etc/cp/conf/tenant_1235_profile_2311/policy.json"))
        .WillOnce(Return(string("checksum_policy_tenant_1235")));

    EXPECT_CALL(mock_orchestration_tools, readFile("/etc/cp/conf/tenant_1236_profile_2611/policy.json"))
        .WillOnce(Return(string("{}")));

    EXPECT_CALL(mock_orchestration_tools, readFile("/etc/cp/conf/tenant_1235_profile_2311/policy.json"))
        .WillOnce(Return(string("{}")));


    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, "/etc/cp/conf/tenant_1236_profile_2611_settings.json"))
        .WillOnce(Return(string("checksum_settings_tenant_1236")));

    EXPECT_CALL(mock_orchestration_tools, calculateChecksum(_, "/etc/cp/conf/tenant_1235_profile_2311_settings.json"))
        .WillOnce(Return(string("checksum_settings_tenant_1235")));

    EXPECT_CALL(mock_update_communication, getUpdate(_)).WillOnce(
        Invoke(
            [&](CheckUpdateRequest &req)
            {
                EXPECT_THAT(req.getPolicy(), IsValue(policy_checksum));
                EXPECT_THAT(req.getSettings(), IsValue(settings_checksum));
                EXPECT_THAT(req.getManifest(), IsValue(manifest_checksum));
                EXPECT_THAT(req.getData(), IsValue(data_checksum));

                string update_response =
                    "{\n"
                    "    \"manifest\": \"\",\n"
                    "    \"policy\": \"\",\n"
                    "    \"settings\": \"\",\n"
                    "    \"data\": \"\",\n"
                    "    \"virtualPolicy\": {\n"
                    "        \"tenants\": [\n"
                    "            {\n"
                    "                \"tenantId\": \"1236\",\n"
                    "                \"profileId\": \"2611\",\n"
                    "                \"checksum\": \"new_checksum_policy_tenant_1236\",\n"
                    "                \"version\": \"1\"\n"
                    "            },\n"
                    "            {\n"
                    "                \"tenantId\": \"1235\",\n"
                    "                \"profileId\": \"2311\",\n"
                    "                \"checksum\": \"new_checksum_policy_tenant_1235\",\n"
                    "                \"version\": \"1\"\n"
                    "            }\n"
                    "        ]\n"
                    "    },\n"
                    "    \"virtualSettings\": {\n"
                    "        \"tenants\": [\n"
                    "            {\n"
                    "                \"tenantId\": \"1236\",\n"
                    "                \"profileId\": \"2611\",\n"
                    "                \"checksum\": \"new_checksum_settings_tenant_1236\",\n"
                    "                \"version\": \"1\"\n"
                    "            },\n"
                    "            {\n"
                    "                \"tenantId\": \"1235\",\n"
                    "                \"profileId\": \"2311\",\n"
                    "                \"checksum\": \"new_checksum_settings_tenant_1235\",\n"
                    "                \"version\": \"1\"\n"
                    "            }\n"
                    "        ]\n"
                    "    }\n"
                    "}";

                EXPECT_TRUE(req.loadJson(update_response));

                return Maybe<void>();
            }
        )
    );

    GetResourceFile policy_file(GetResourceFile::ResourceFileType::VIRTUAL_POLICY);
    policy_file.addTenant("1236", "2611", "1", "new_checksum_policy_tenant_1236");
    policy_file.addTenant("1235", "2311", "1", "new_checksum_policy_tenant_1235");

    map<pair<string, string>, string> download_policy_res = {
        { {"1236", "2611" }, "/tmp/orchestration_downloads/virtualPolicy_1236_profile_2611.download" },
        { {"1235", "2311" }, "/tmp/orchestration_downloads/virtualPolicy_1235_profile_2311.download" }
    };

    GetResourceFile settings_file(GetResourceFile::ResourceFileType::VIRTUAL_SETTINGS);
    settings_file.addTenant("1236", "2611", "1", "new_checksum_settings_tenant_1236");
    settings_file.addTenant("1235", "2311", "1", "new_checksum_settings_tenant_1235");

    map<pair<string, string>, string> download_settings_res = {
        { {"1236", "2611" }, "/tmp/orchestration_downloads/virtualSettings_1236_profile_2611.download" },
        { {"1235", "2311" }, "/tmp/orchestration_downloads/virtualSettings_1235_profile_2311.download" }
    };

    EXPECT_CALL(
        mock_downloader,
        downloadVirtualFileFromFog(_, Package::ChecksumTypes::SHA256)
    ).WillOnce(
        WithArg<0>(
            Invoke(
                [&] (const GetResourceFile &resourse_file)
                {
                    EXPECT_EQ(resourse_file, policy_file);
                    return download_policy_res;
                }
            )
        )
    ).WillOnce(
        WithArg<0>(
            Invoke(
                [&] (const GetResourceFile &resourse_file)
                {
                    EXPECT_EQ(resourse_file, settings_file);
                    return download_settings_res;
                }
            )
        )
    );

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(
            "/tmp/orchestration_downloads/virtualSettings_1236_profile_2611.download",
            "/etc/cp/conf/tenant_1236_profile_2611_settings.json"
        )
    ).WillOnce(Return(true));

    EXPECT_CALL(
        mock_orchestration_tools,
        copyFile(
            "/tmp/orchestration_downloads/virtualSettings_1235_profile_2311.download",
            "/etc/cp/conf/tenant_1235_profile_2311_settings.json"
        )
    ).WillOnce(Return(true));

    vector<string> expected_data_types = {};
    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(
            "/etc/cp/conf/policy.json",
            "/etc/cp/conf/settings.json",
            expected_data_types,
            "",
            "",
            false
        )
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(
            "/tmp/orchestration_downloads/virtualPolicy_1236_profile_2611.download",
            "/etc/cp/conf/tenant_1236_profile_2611_settings.json",
            expected_data_types,
            "1236",
            "2611",
            false
        )
    ).WillOnce(Return(Maybe<void>()));

    EXPECT_CALL(
        mock_service_controller,
        updateServiceConfiguration(
            "/tmp/orchestration_downloads/virtualPolicy_1235_profile_2311.download",
            "/etc/cp/conf/tenant_1235_profile_2311_settings.json",
            expected_data_types,
            "1235",
            "2311",
            true
        )
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
    EXPECT_CALL(mock_orchestration_tools, deleteVirtualTenantProfileFiles("321321", "123123", "/etc/cp/conf/"))
    .Times(1);
    try {
        runRoutine();
    } catch (const invalid_argument& e) {}
    Debug::setNewDefaultStdout(&cout);
}
