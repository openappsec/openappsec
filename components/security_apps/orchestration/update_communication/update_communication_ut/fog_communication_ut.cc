#ifndef DISABLE_APPSEC_DATA_ENCRYPTION
#include <string>

#include "fog_communication.h"
#include "version.h"
#include "cptest.h"
#include "mainloop.h"
#include "time_proxy.h"
#include "config.h"
#include "config_component.h"
#include "agent_details.h"
#include "declarative_policy_utils.h"
#include "local_policy_mgmt_gen.h"
#include "mock/mock_env_details.h"

#include "mock/mock_orchestration_status.h"
#include "mock/mock_orchestration_tools.h"
#include "mock/mock_details_resolver.h"
#include "mock/mock_messaging.h"
#include "mock/mock_messaging.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_shell_cmd.h"
#include "mock/mock_encryptor.h"
#include "mock/mock_rest_api.h"

using namespace std;
using namespace testing;

ostream &
operator<<(ostream &os, const Maybe<tuple<OrchManifest, OrchPolicy, OrchSettings>> &)
{
    return os;
}

unique_ptr<ServerRest> rest_handler;
unique_ptr<ServerRest> declare_variable;
unique_ptr<ServerRest> apply_policy;

bool restHandler(const unique_ptr<RestInit> &p) { rest_handler = p->getRest(); return true; }
bool declareVariable(const unique_ptr<RestInit> &p) { declare_variable = p->getRest(); return true; }
bool applyPolicy(const unique_ptr<RestInit> &p) { apply_policy = p->getRest(); return true; }

class FogCommunicationTest: public Test
{
public:
    FogCommunicationTest()
    {
        EXPECT_CALL(mock_rs, mockRestCall(RestAction::SHOW, "version-info", _)).WillOnce(Return(true));
        EXPECT_CALL(
            mock_rs,
            mockRestCall(RestAction::SHOW, "access-token", _)
        ).WillOnce(WithArg<2>(Invoke(restHandler)));

        EXPECT_CALL(
            mock_rs,
            mockRestCall(RestAction::ADD, "declare-boolean-variable", _)
        ).WillOnce(WithArg<2>(Invoke(declareVariable)));

        EXPECT_CALL(mock_rs, mockRestCall(RestAction::SET, "apply-policy", _))
            .WillOnce(WithArg<2>(Invoke(applyPolicy))
        );

        env.preload();
        env.init();
        Version::init();
        declarative_policy.init();
    }

    ~FogCommunicationTest()
    {
        env.fini();
    }

    void
    init()
    {
        fog_communication.init();
    }

    void
    preload()
    {
        fog_communication.preload();
    }

    Maybe<void>
    sendPolicyVersion(const string &policy_version, const string &policy_versions)
    {
        return fog_communication.sendPolicyVersion(policy_version, policy_versions);
    }

    Maybe<void>
    authenticateAgent()
    {
        return fog_communication.authenticateAgent();
    }

    Maybe<string>
    downloadAttributeFile(const GetResourceFile &resourse_file, const string &file_path)
    {
        return fog_communication.downloadAttributeFile(resourse_file, file_path);
    }

    void setFogExtension(const string &ex)
    {
        fog_communication.setAddressExtenesion(ex);
    }

    Maybe<void>
    checkUpdate(CheckUpdateRequest &req)
    {
        return fog_communication.getUpdate(req);
    }

    void
    expectTokenRequest()
    {
        HTTPResponse res(
            HTTPStatusCode::HTTP_OK,
            string(
                "{"
                "    \"access_token\": \"" + clear_access_token + "\","
                "    \"token_type\": \"basic\","
                "    \"expires_in\": 100,"
                "    \"scope\": \"idk\","
                "    \"uuid\": \"user_id\","
                "    \"jti\": \"jti-id\""
                "}"
            )
        );

        EXPECT_CALL(
            mock_message,
            sendSyncMessage(
                HTTPMethod::POST,
                "/oauth/token?grant_type=client_credentials",
                "",
                _,
                _
            )
        ).WillOnce(Return(res));
    }

    void
    expectAuthenticationData(const string &req_body)
    {
        EXPECT_CALL(
            mock_message,
            sendSyncMessage(
                HTTPMethod::POST,
                "/agents",
                req_body,
                _,
                _
            )
        ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, clear_cred_body)));
    }

    void
    expectCheckupdateRequest(const string &req_body, const string &res_body)
    {
        EXPECT_CALL(
            mock_message,
            sendSyncMessage(
                HTTPMethod::POST,
                "/api/v2/agents/resources",
                req_body,
                _,
                _
            )
        ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, res_body)));
    }

    void
    setUpgradeFields(CheckUpdateRequest &req)
    {
        auto upgrade_mode = getSettingWithDefault<string>("manual", "upgradeMode");
        if (upgrade_mode != "scheduled") {
            req.setUpgradeFields(upgrade_mode);
        } else {
            req.setUpgradeFields(
                upgrade_mode,
                getSettingWithDefault<string>("0:00", "upgradeTime"),
                getSettingWithDefault<uint>(4, "upgradeDurationHours"),
                getSettingWithDefault<vector<string>>({}, "upgradeDay")
            );
        }
    }

    ::Environment env;
    AgentDetails agent_details;
    ConfigComponent config_comp;
    LocalPolicyMgmtGenerator local_policy_gen;
    DeclarativePolicyUtils declarative_policy;
    StrictMock<EnvDetailsMocker> mock_env_details;
    StrictMock<MockRestApi> mock_rs;
    StrictMock<MockMainLoop> mock_ml;
    StrictMock<MockMessaging> mock_message;
    StrictMock<MockOrchestrationTools> mock_ot;
    StrictMock<MockOrchestrationStatus> mock_status;
    StrictMock<MockDetailsResolver> mock_details_resolver;
    NiceMock<MockTimeGet> time;
    StrictMock<MockShellCmd> mock_shell_cmd;
    StrictMock<MockEncryptor> mock_encryptor;
    string clear_access_token = "BEST ACCESS TOKEN EVER";
    string base64_access_token = "dsadadsadsa";
    string agent_id   = "35f5a31a-d333-47bf-bc61-6912cdbd96bc";
    string profile_id = "077aa3c2-82e0-405f-802b-225dc3c16bf3";
    string tenant_id = "7bb5aab4-cc81-4724-bc87-9c0616cd562d";
    string encrypted_access_token = "dsadadsadsa";
    Maybe<string> mb_encrypted_access_token = encrypted_access_token;
    string clear_cred_body =
        "{"
        "    \"client_id\":\"user id\","
        "    \"shared_secret\": \"best shared secret\","
        "    \"tenantId\": \"" + tenant_id + "\","
        "    \"profileId\": \"" + profile_id + "\","
        "    \"agentId\": \"" + agent_id + "\""
        "}";
    string clear_cred =  "{\n    \"client_id\": \"user id\",\n    \"shared_secret\": \"best shared secret\"\n}";
    string encrypted_cred = "adsadasdsadadsa"; // Not real base64, just for test
    string clear_otp =
        "{\n"
        "    \"registration type\": \"token\",\n"
        "    \"registration data\": \"This is the best OTP token\",\n"
        "    \"expired\": false\n"
        "}\n";

    string base64_otp = "adsadasdsadadsa"; // Not real base64, just for test
    Maybe<string> mb_base64_otp = base64_otp;
    string data_path = "/etc/cp/data/";

    const string required_apps_file_path = "/etc/cp/conf/support-practices.txt";

private:
    FogCommunication fog_communication;
};

TEST_F(FogCommunicationTest, doNothing)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
}

TEST_F(FogCommunicationTest, register_config)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();

    preload();
    string config_json =
        "{\n"
        "    \"orchestration\": {\n"
        "        \"OTP Token Path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"ABC\"\n"
        "            }\n"
        "        ],\n"
        "        \"User Credentials Path\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"qwe\"\n"
        "            }\n"
        "        ],\n"
        "        \"Agent type\": [\n"
        "            {\n"
        "                \"context\": \"All()\",\n"
        "                \"value\": \"CCCC\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}";
    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config_comp)->loadConfiguration(ss);

    EXPECT_THAT(getConfiguration<string>("orchestration", "OTP Token Path"),        IsValue("ABC"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "User Credentials Path"), IsValue("qwe"));
    EXPECT_THAT(getConfiguration<string>("orchestration", "Agent type"),            IsValue("CCCC"));
}

TEST_F(FogCommunicationTest, authenticateAgentFromGivenCredentials)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(encrypted_cred));
    EXPECT_CALL(mock_encryptor, aes256DecryptWithSizePad(encrypted_cred)).WillOnce(Return(clear_cred));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping of the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)).WillOnce(Return(encrypted_access_token)
    );
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());
}

TEST_F(FogCommunicationTest, authenticateAgentFromOTPToken)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Fog ext
    setFogExtension("test");

    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(true));

    map<string, string> resolved_mgmt_details({{"cpProductIntegrationMgmtObjectType", "management"}});
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(resolved_mgmt_details));

    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"cpProductIntegrationMgmtObjectType\": \"management\",\n"
        "            \"isGwNotVsx\": \"true\",\n"
        "            \"isKernelVersion3OrHigher\": \"true\",\n"
        "            \"isVersionEqualOrAboveR8110\": \"true\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_access_token))
        .WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());
}

TEST_F(FogCommunicationTest, authenticateAgentFromEnvOTPToken)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Fog ext
    setFogExtension("test");

    char env_token[] = "NANO_AGENT_TOKEN=ThisIsAMochToken";
    putenv(env_token);

    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"ThisIsAMochToken\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"isGwNotVsx\": \"true\",\n"
        "            \"isKernelVersion3OrHigher\": \"true\",\n"
        "            \"isVersionEqualOrAboveR8110\": \"true\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_access_token))
        .WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());
    unsetenv("NANO_AGENT_TOKEN");
}

TEST_F(FogCommunicationTest, registrationWithRequiredApps)
{
    vector<string> intel_file_content({"waap", "accessControl", "ips"});
    CPTestTempfile file(intel_file_content);
    setConfiguration(file.fname, "orchestration", "Supported practices file path");
    EXPECT_CALL(mock_ot, doesFileExist(file.fname)).WillOnce(Return(true));
    init();
    // Fog ext
    setFogExtension("test");

    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"require\": \"waap;accessControl;ips\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));

    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());
}

TEST_F(FogCommunicationTest, registrationWithRequiredAppsNginx)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Fog ext
    setFogExtension("test");

    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Reading agent details for registration
    Maybe<tuple<string, string, string>> nginx_data = make_tuple(
        string("--prefix=/etc/nginx --conf=/etc/nginx.conf --log-path=/log/a.log"),
        string("-g -O2 -fstack-protecr-strong -Wformat -Werror=format-security"),
        string("nginx-1.10.3")
    );

    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(nginx_data));
        EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"configureOpt\": \"--prefix=/etc/nginx --conf=/etc/nginx.conf --log-path=/log/a.log\",\n"
        "            \"extraCompilerOpt\": \"-g -O2 -fstack-protecr-strong -Wformat -Werror=format-security\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"nginxVersion\": \"nginx-1.10.3\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));

    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());
}

TEST_F(FogCommunicationTest, authenticateAgentFromOTPTokenFailedWriteToFile)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Fog ext
    setFogExtension("test");

    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
#ifndef DISABLE_APPSEC_DATA_ENCRYPTION
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).Times(2).WillRepeatedly(Return(mb_base64_otp));
#endif // DISABLE_APPSEC_DATA_ENCRYPTION
    I_MainLoop::Routine rewrite_routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::Offline, _, _, false))
        .WillOnce(DoAll(SaveArg<1>(&rewrite_routine), Return(1)));
#ifndef DISABLE_APPSEC_DATA_ENCRYPTION
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false))
        .WillOnce(Return(false)) // Will retry after 1 min
        .WillOnce(Return(true));
#endif // DISABLE_APPSEC_DATA_ENCRYPTION
#ifdef DISABLE_APPSEC_DATA_ENCRYPTION
    EXPECT_CALL(mock_ot, writeFile(clear_cred, data_path + user_cred_file_name, false))
            .WillOnce(Return(false)) // Will retry after 1 min
            .WillOnce(Return(true));
#endif // DISABLE_APPSEC_DATA_ENCRYPTION

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));
    expectTokenRequest();

#ifndef DISABLE_APPSEC_DATA_ENCRYPTION
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
#endif // DISABLE_APPSEC_DATA_ENCRYPTION

#ifdef DISABLE_APPSEC_DATA_ENCRYPTION
    EXPECT_CALL(
        mock_ot,
        writeFile(clear_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
#endif // DISABLE_APPSEC_DATA_ENCRYPTION

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [] (chrono::microseconds microseconds)
                {
                    EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                    throw invalid_argument("stop while loop");
                }
            )
        );
    try {
        routine();
    } catch (const invalid_argument& e) {
        try {
            rewrite_routine();
        } catch (const invalid_argument& e) {}
    }
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    string obfuscatedToken = "102123021002132312312312312";
    EXPECT_CALL(mock_encryptor, obfuscateXorBase64("BEST ACCESS TOKEN EVER")).WillOnce(Return(obfuscatedToken));
    stringstream is;
    is << "{}";
    auto output = rest_handler->performRestCall(is);

    string res =
        "{\n"
        "    \"token\": \"" + obfuscatedToken + "\",\n"
        "    \"expiration\": 100\n"
        "}";
    EXPECT_THAT(output, IsValue(res));
}

TEST_F(FogCommunicationTest, invalidCheckUpdate)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "0");
    EXPECT_THAT(checkUpdate(req), IsError("Acccess Token not available."));
}

TEST_F(FogCommunicationTest, checkUpdate)
{
    setSetting<string>("scheduled", "upgradeMode");
    setSetting<string>("13:00", "upgradeTime");
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status, setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_access_token))
        .WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"12\",\n"
        "    \"localConfigurationSettings\": {\n"
        "        \"upgradeSchedule\": {\n"
        "            \"upgradeMode\": \"scheduled\",\n"
        "            \"upgradeTime\": \"13:00\",\n"
        "            \"upgradeDurationHours\": 4\n"
        "        }\n"
        "    }\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\""
        "}"
    );
    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "12");
    setUpgradeFields(req);
    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("B"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
    EXPECT_THAT(req.getData(), IsValue("D"));
}

TEST_F(FogCommunicationTest, checkUpdateDeclarativeMode)
{
    EXPECT_CALL(mock_env_details, getEnvType()).WillRepeatedly(Return(EnvType::LINUX));

    setSetting<string>("declarative", "profileManagedMode");
    setSetting<string>("scheduled", "upgradeMode");
    setSetting<string>("13:00", "upgradeTime");
    setSetting<uint>(6, "upgradeDurationHours");
    setSetting<vector<string>>({"Sunday", "Monday"}, "upgradeDay");
    Maybe<string> checksum_value(string("12345"));
    EXPECT_CALL(mock_ot, calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        _)).WillRepeatedly(Return(checksum_value));
    EXPECT_CALL(mock_shell_cmd, getExecOutput(_, _, _)).WillRepeatedly(Return(checksum_value));

    string policy_path = "/etc/cp/conf/local_policy.yaml";
    stringstream is;
    is << "{\"policy_path\": \""+ policy_path +"\"}";
    auto output = apply_policy->performRestCall(is);

    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"declarative\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));

    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"12\",\n"
        "    \"localConfigurationSettings\": {\n"
        "        \"upgradeSchedule\": {\n"
        "            \"upgradeMode\": \"scheduled\",\n"
        "            \"upgradeTime\": \"13:00\",\n"
        "            \"upgradeDurationHours\": 6,\n"
        "            \"upgradeDay\": [\n"
        "                \"Sunday\",\n"
        "                \"Monday\"\n"
        "            ]\n"
        "        }\n"
        "    }\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\""
        "}"
    );
    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "12");
    setUpgradeFields(req);
    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("12345"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
    EXPECT_THAT(req.getData(), IsValue("D"));
}

TEST_F(FogCommunicationTest, emptyCheckUpdate)
{
    setSetting<string>("scheduled", "upgradeMode");
    setSetting<string>("13:00", "upgradeTime");
    setSetting<uint>(6, "upgradeDurationHours");
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(encrypted_cred));
    EXPECT_CALL(mock_encryptor, aes256DecryptWithSizePad(encrypted_cred)).WillOnce(Return(clear_cred));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping og the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"A\",\n"
        "    \"policy\": \"B\",\n"
        "    \"settings\": \"C\",\n"
        "    \"data\": \"D\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"12\",\n"
        "    \"localConfigurationSettings\": {\n"
        "        \"upgradeSchedule\": {\n"
        "            \"upgradeMode\": \"scheduled\",\n"
        "            \"upgradeTime\": \"13:00\",\n"
        "            \"upgradeDurationHours\": 6\n"
        "        }\n"
        "    }\n"
        "}",
        "{"
        "   \"manifest\" : \"\","
        "   \"policy\" : \"\","
        "   \"settings\" : \"\","
        "   \"data\" : \"\""
        "}"
    );

    CheckUpdateRequest req("A", "B", "C", "D", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "12");
    setUpgradeFields(req);
    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsError("No manifest"));
    EXPECT_THAT(req.getPolicy(), IsError("No policy"));
    EXPECT_THAT(req.getSettings(), IsError("No settings"));
}

TEST_F(FogCommunicationTest, downloadFile)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(encrypted_cred));
    EXPECT_CALL(mock_encryptor, aes256DecryptWithSizePad(encrypted_cred)).WillOnce(Return(clear_cred));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping og the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Downloading file
    string response = "Best Attribute file";
    EXPECT_CALL(
        mock_message,
        downloadFile(
            HTTPMethod::GET,
            "/api/v2/agents/resources/manifest",
            "/tmp/orch_files/",
            _,
            _
        )
    ).WillOnce(Return(Maybe<HTTPStatusCode, HTTPResponse>(HTTPStatusCode::HTTP_OK)));

    GetResourceFile manifest_file(GetResourceFile::ResourceFileType::MANIFEST);
    EXPECT_THAT(downloadAttributeFile(manifest_file, "/tmp/orch_files/"), IsValue("/tmp/orch_files/"));
}

TEST_F(FogCommunicationTest, downloadFileDeclarativeMode)
{
    setSetting<string>("declarative", "profileManagedMode");
    Maybe<string> checksum_value(string("12345"));
    EXPECT_CALL(mock_ot, calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        _)).WillRepeatedly(Return(checksum_value));
    EXPECT_CALL(mock_shell_cmd, getExecOutput(_, _, _)).WillRepeatedly(Return(checksum_value));

    ApplyPolicyEvent apply_policy_event;
    apply_policy_event.notify();

    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(encrypted_cred));
    EXPECT_CALL(mock_encryptor, aes256DecryptWithSizePad(encrypted_cred)).WillOnce(Return(clear_cred));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping og the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Downloading file
    GetResourceFile policy_file(GetResourceFile::ResourceFileType::POLICY);
    EXPECT_THAT(downloadAttributeFile(policy_file, "/tmp/orch_files/"), IsValue(""));
}

TEST_F(FogCommunicationTest, changeRenewToken)
{
    setSetting<string>("automatic", "upgradeMode");
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();

    preload();

    // Set new configuration
    setConfiguration<int>(100, "fog communication", "Time (seconds) to renew token prior its expiration");

    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));
    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(
        mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "linux", "x86_64")
    );
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);
    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("linux")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"linux\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());
    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_access_token))
        .WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );

    // Running the routine
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"12\",\n"
        "    \"localConfigurationSettings\": {\n"
        "        \"upgradeSchedule\": {\n"
        "            \"upgradeMode\": \"automatic\"\n"
        "        }\n"
        "    }\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\""
        "}"
    );

    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "12");
    setUpgradeFields(req);
    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("B"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
}

TEST_F(FogCommunicationTest, sendPolicyVersion)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    string msg = "";

    EXPECT_CALL(
        mock_message,
        sendSyncMessage(
            HTTPMethod::PATCH,
            "/agents",
            "{ \"policyVersion\" :\"12\", \"versions\": [\n"
            "{\n"
            "    \"name\": \"Max\",\n"
            "    \"id\": \"12345\",\n"
            "    \"version\": 5\n},\n"
            "{\n"
            "    \"name\": \"Tom\",\n"
            "    \"id\": \"67890\",\n"
            "    \"version\": 6\n"
            "}]}",
            _,
            _
        )
    ).WillOnce(Return(HTTPResponse(HTTPStatusCode::HTTP_OK, msg)));
    string policy_versions =
        "[\n"
            "{\n"
            "    \"name\": \"Max\",\n"
            "    \"id\": \"12345\",\n"
            "    \"version\": 5\n},\n"
            "{\n"
            "    \"name\": \"Tom\",\n"
            "    \"id\": \"67890\",\n"
            "    \"version\": 6\n"
        "}]";
    sendPolicyVersion("12", policy_versions);
}

TEST_F(FogCommunicationTest, virtual_check_update)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": [\n"
        "            {\n"
        "                \"tenantId\": \"\",\n"
        "                \"profileId\": \"\",\n"
        "                \"checksum\": \"\",\n"
        "                \"version\": \"\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"1\",\n"
        "                \"profileId\": \"4\",\n"
        "                \"checksum\": \"2\",\n"
        "                \"version\": \"3\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"tenant_id\",\n"
        "                \"profileId\": \"profile_id\",\n"
        "                \"checksum\": \"checksum\",\n"
        "                \"version\": \"version\"\n"
        "            }\n"
        "        ]\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"102\",\n"
        "    \"localConfigurationSettings\": {\n"
        "        \"upgradeSchedule\": {\n"
        "            \"upgradeMode\": \"manual\"\n"
        "        }\n"
        "    }\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\","
        "   \"virtualPolicy\": {\n"
        "        \"tenants\": [\n"
        "            {\n"
        "                \"tenantId\": \"\",\n"
        "                \"profileId\": \"\",\n"
        "                \"checksum\": \"\",\n"
        "                \"version\": \"\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"1\",\n"
        "                \"profileId\": \"4\",\n"
        "                \"checksum\": \"2\",\n"
        "                \"version\": \"3\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"tenant_id\",\n"
        "                \"profileId\": \"profile_id\",\n"
        "                \"checksum\": \"checksum\",\n"
        "                \"version\": \"version\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}"
    );
    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "102");
    req.addTenantPolicy("", "", "", "");
    req.addTenantPolicy("1", "4", "2", "3");
    req.addTenantPolicy("tenant_id", "profile_id", "checksum", "version");
    setUpgradeFields(req);

    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("B"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
    EXPECT_THAT(req.getData(), IsValue("D"));

    auto res = req.getVirtualPolicy();
    EXPECT_TRUE(res.ok());

    vector<CheckUpdateRequest::Tenants> exp;

    exp.push_back(CheckUpdateRequest::Tenants("", "", "", ""));
    exp.push_back(CheckUpdateRequest::Tenants("1", "4", "2", "3"));
    exp.push_back(CheckUpdateRequest::Tenants("tenant_id", "profile_id", "checksum", "version"));

    EXPECT_THAT(res, exp);
}

TEST_F(FogCommunicationTest, empty_virtual_check_update)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
    EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_access_token))
        .WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": [\n"
        "            {\n"
        "                \"tenantId\": \"\",\n"
        "                \"profileId\": \"\",\n"
        "                \"checksum\": \"\",\n"
        "                \"version\": \"\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"1\",\n"
        "                \"profileId\": \"4\",\n"
        "                \"checksum\": \"2\",\n"
        "                \"version\": \"3\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"tenant_id\",\n"
        "                \"profileId\": \"profile_id\",\n"
        "                \"checksum\": \"checksum\",\n"
        "                \"version\": \"version\"\n"
        "            }\n"
        "        ]\n"
        "    },\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"102\"\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\""
        "}"

    );

    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "102");
    req.addTenantPolicy("", "", "", "");
    req.addTenantPolicy("1", "4", "2", "3");
    req.addTenantPolicy("tenant_id", "profile_id", "checksum", "version");


    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("B"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
    EXPECT_THAT(req.getData(), IsValue("D"));

    auto res = req.getVirtualPolicy();
    EXPECT_FALSE(res.ok());
}

TEST_F(FogCommunicationTest, greedy_check_update)
{
    EXPECT_CALL(mock_ot, doesFileExist(required_apps_file_path)).WillOnce(Return(false));
    init();
    // Reading user cred
    Maybe<string> no_cred_err(genError("No Credentials file"));
    EXPECT_CALL(mock_ot, readFile(data_path + user_cred_file_name)).WillOnce(Return(no_cred_err));

    // Reading OTP
    EXPECT_CALL(mock_ot, readFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(base64_otp));
    EXPECT_CALL(mock_ot, base64Decode(base64_otp)).WillOnce(Return(clear_otp));
    EXPECT_CALL(mock_ot, removeFile("/etc/cp/conf/registration-data.json")).WillOnce(Return(true));

    // Reading agent details for registration
    Maybe<tuple<string, string, string>> no_nginx(genError("No nginx"));
    EXPECT_CALL(mock_details_resolver, getHostname()).WillOnce(Return(string("smartmeter")));
    EXPECT_CALL(mock_details_resolver, getPlatform()).WillOnce(Return(string("gaia")));
    EXPECT_CALL(mock_details_resolver, getArch()).WillOnce(Return(string("x86_64")));
    EXPECT_CALL(mock_details_resolver, isReverseProxy()).WillOnce(Return(true));
    EXPECT_CALL(mock_details_resolver, isKernelVersion3OrHigher()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isGwNotVsx()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, isVersionEqualOrAboveR8110()).WillOnce(Return(false));
    EXPECT_CALL(mock_details_resolver, getResolvedDetails()).WillOnce(Return(map<string, string>()));
    EXPECT_CALL(mock_details_resolver, parseNginxMetadata()).WillOnce(Return(no_nginx));
        EXPECT_CALL(mock_details_resolver, getAgentVersion())
        .WillOnce(Return(Version::getFullVersion()))
        .WillOnce(Return(Version::getFullVersion()));

    EXPECT_CALL(mock_status, setAgentDetails(agent_id, profile_id, tenant_id));
    EXPECT_CALL(mock_status,
        setRegistrationDetails("smartmeter", "Embedded", "gaia", "x86_64"));
    EXPECT_CALL(
        mock_status,
        setFieldStatus(OrchestrationStatusFieldType::REGISTRATION, OrchestrationStatusResult::SUCCESS, "")
    ).Times(2);

    // Sending cred request
    expectAuthenticationData(
        "{\n"
        "    \"authenticationData\": [\n"
        "        {\n"
        "            \"authenticationMethod\": \"token\",\n"
        "            \"data\": \"This is the best OTP token\"\n"
        "        }\n"
        "    ],\n"
        "    \"metaData\": {\n"
        "        \"agentName\": \"smartmeter\",\n"
        "        \"agentType\": \"Embedded\",\n"
        "        \"platform\": \"gaia\",\n"
        "        \"architecture\": \"x86_64\",\n"
        "        \"agentVersion\": \"" + Version::getFullVersion() + "\",\n"
        "        \"additionalMetaData\": {\n"
        "            \"agent_version\": \"" + Version::getFullVersion() + "\",\n"
        "            \"managedMode\": \"management\",\n"
        "            \"reverse_proxy\": \"true\",\n"
        "            \"userEdition\": \"PrEm1um%\"\n"
        "        }\n"
        "    }\n"
        "}"
    );

    // Saving cred
    EXPECT_CALL(mock_encryptor, aes256EncryptWithSizePad(clear_cred)).WillOnce(Return(mb_base64_otp));
    EXPECT_CALL(mock_ot, writeFile(base64_otp, data_path + user_cred_file_name, false)).WillOnce(Return(true));

    // Creating the session token routine
    EXPECT_CALL(mock_ml, doesRoutineExist(0)).WillOnce(Return(false));
    I_MainLoop::Routine routine;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, _, _, true))
        .WillOnce(DoAll(SaveArg<1>(&routine), Return(1)));
    EXPECT_CALL(mock_ml, yield(chrono::microseconds(11000000)));
    EXPECT_FALSE(authenticateAgent().ok());

    // Looping the routine
    EXPECT_CALL(mock_ot, base64Encode("user id:best shared secret"))
        .WillOnce(Return(string("dXNlciBpZDpiZXN0IHNoYXJlZCBzZWNyZXQ=")));

    expectTokenRequest();
    EXPECT_CALL(
        mock_encryptor,
        aes256EncryptWithSizePad(clear_access_token)
    ).WillOnce(Return(mb_encrypted_access_token));
    EXPECT_CALL(
        mock_ot,
        writeFile(encrypted_access_token, data_path + session_token_file_name, false)).WillOnce(Return(true)
    );
    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillOnce(
        Invoke(
            [] (chrono::microseconds microseconds)
            {
                EXPECT_EQ(10000000, microseconds.count()); // Validate short expiration time, mininum is 10 sec
                throw invalid_argument("stop while loop");
            }
        )
    );
    try {
        routine();
    } catch (const invalid_argument& e) {}
    EXPECT_CALL(mock_ml, doesRoutineExist(1)).WillOnce(Return(true));
    EXPECT_TRUE(authenticateAgent().ok());

    // Sending checkupdate request
    expectCheckupdateRequest(
        "{\n"
        "    \"manifest\": \"\",\n"
        "    \"policy\": \"\",\n"
        "    \"settings\": \"\",\n"
        "    \"data\": \"\",\n"
        "    \"virtualSettings\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"virtualPolicy\": {\n"
        "        \"tenants\": []\n"
        "    },\n"
        "    \"checkForAllTenants\": true,\n"
        "    \"checksum-type\": \"sha256sum\",\n"
        "    \"policyVersion\": \"102\"\n"
        "}",
        "{"
        "   \"manifest\" : \"A\","
        "   \"policy\" : \"B\","
        "   \"settings\" : \"C\","
        "   \"data\" : \"D\","
        "   \"virtualPolicy\": {\n"
        "        \"tenants\": [\n"
        "            {\n"
        "                \"tenantId\": \"\",\n"
        "                \"profileId\": \"\",\n"
        "                \"checksum\": \"\",\n"
        "                \"version\": \"\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"1\",\n"
        "                \"profileId\": \"4\",\n"
        "                \"checksum\": \"2\",\n"
        "                \"version\": \"3\"\n"
        "            },\n"
        "            {\n"
        "                \"tenantId\": \"tenant_id\",\n"
        "                \"profileId\": \"profile_id\",\n"
        "                \"checksum\": \"checksum\",\n"
        "                \"version\": \"version\"\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}"
    );

    CheckUpdateRequest req("", "", "", "", I_OrchestrationTools::SELECTED_CHECKSUM_TYPE_STR, "102");
    req.setGreedyMode();

    auto response = checkUpdate(req);
    EXPECT_TRUE(response.ok());

    EXPECT_THAT(req.getManifest(), IsValue("A"));
    EXPECT_THAT(req.getPolicy(), IsValue("B"));
    EXPECT_THAT(req.getSettings(), IsValue("C"));
    EXPECT_THAT(req.getData(), IsValue("D"));

    auto res = req.getVirtualPolicy();
    EXPECT_TRUE(res.ok());

    vector<CheckUpdateRequest::Tenants> exp;

    exp.push_back(CheckUpdateRequest::Tenants("", "", "", ""));
    exp.push_back(CheckUpdateRequest::Tenants("1", "4", "2", "3"));
    exp.push_back(CheckUpdateRequest::Tenants("tenant_id", "profile_id", "checksum", "version"));

    EXPECT_THAT(res, exp);
}

#endif //DISABLE_APPSEC_DATA_ENCRYPTION
