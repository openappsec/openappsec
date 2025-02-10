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

#include "fog_communication.h"
#include "rest.h"
#include "config.h"
#include "log_generator.h"
#include "agent_details.h"
#include "version.h"
#include "i_messaging.h"

#include <algorithm>
#include <map>
#include <vector>

using namespace std;
using namespace cereal;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

function<Maybe<FogAuthenticator::AccessToken>()> FogAuthenticator::AccessTokenProvider::getAccessToken = nullptr;

FogAuthenticator::AccessToken::AccessToken(const string &_token, chrono::seconds _expiration)
        :
    token(_token),
    expiration(_expiration)
{
    received_time = Singleton::Consume<I_TimeGet>::by<FogAuthenticator>()->getMonotonicTime();
}

chrono::seconds
FogAuthenticator::AccessToken::getRemainingTime() const
{
    return
        expiration -
        chrono::duration_cast<chrono::seconds>(
            Singleton::Consume<I_TimeGet>::by<FogAuthenticator>()->getMonotonicTime() - received_time
        );
}

void
FogAuthenticator::AccessTokenProvider::doCall()
{
    if (getAccessToken != nullptr) {
        auto access_token = getAccessToken();
        if (access_token.ok()) {
            auto encryptor = Singleton::Consume<I_Encryptor>::by<FogAuthenticator>();
            token = encryptor->obfuscateXorBase64(access_token.unpack().getToken());
            expiration = access_token.unpack().getRemainingTime().count();
        }
    }
}

FogAuthenticator::RegistrationData::RegistrationData(const string &token)
        :
    type(AuthenticationType::Token),
    data(token)
{
}

string
FogAuthenticator::RegistrationData::getData() const
{
    return data;
}

FogAuthenticator::UserCredentials::UserCredentials(const string &_client_id, const string &_shared_secret)
        :
    client_id(_client_id),
    shared_secret(_shared_secret)
{
}

void
FogAuthenticator::UserCredentials::serialize(JSONOutputArchive &out_ar) const
{
    out_ar(
        make_nvp("client_id",       client_id),
        make_nvp("shared_secret",   shared_secret)
    );
}

void
FogAuthenticator::UserCredentials::serialize(JSONInputArchive &in_ar)
{
    in_ar(
        make_nvp("client_id",       client_id),
        make_nvp("shared_secret",   shared_secret)
    );

    if (client_id.empty() || shared_secret.empty()) {
        throw cereal::Exception("Agent credentials can't be empty.");
    }
}

void
FogAuthenticator::RegistrationData::serialize(JSONInputArchive &in_ar)
{
    string type_as_string;
    static const map<string, AuthenticationType> StringToAuthenticationType {
        { "token",              AuthenticationType::Token },
        { "presharedsecret",    AuthenticationType::PresharedSecret }
    };

    in_ar(
        make_nvp("registration type", type_as_string),
        make_nvp("registration data", data)
    );

    if (type_as_string.empty()) throw cereal::Exception("registration type can't be empty.");
    if (data.empty()) throw cereal::Exception("registration data can't be empty.");

    auto auth_type = StringToAuthenticationType.find(type_as_string);
    if (auth_type == StringToAuthenticationType.end()) throw cereal::Exception("Unsupported registration type.");
    type = auth_type->second;
}

void
FogAuthenticator::RegistrationData::serialize(JSONOutputArchive &out_ar) const
{
    static const EnumArray<AuthenticationType, string> AuthenticationTypeString {
        "token",
        "presharedsecret"
    };

    out_ar(
        make_nvp("authenticationMethod", AuthenticationTypeString[type]),
        make_nvp("data", data)
    );
}

Maybe<FogAuthenticator::UserCredentials>
FogAuthenticator::registerAgent(
    const FogAuthenticator::RegistrationData &reg_data,
    const string &name,
    const string &type,
    const string &platform,
    const string &architecture) const
{
    dbgFlow(D_ORCHESTRATOR) << "Starting agent registration to fog";

    auto details_resolver = Singleton::Consume<I_DetailsResolver>::by<FogAuthenticator>();
    RegistrationRequest request(
        reg_data,
        name,
        type,
        platform,
        architecture,
        details_resolver->getAgentVersion()
    );

    request << make_pair("agent_version", details_resolver->getAgentVersion());

    if (required_security_apps.size() > 0) {
        request << make_pair("require", makeSeparatedStr(required_security_apps, ";"));
    }

    auto nginx_data = details_resolver->parseNginxMetadata();

    if (nginx_data.ok()) {
        string nginx_version;
        string config_opt;
        string cc_opt;
        tie(config_opt, cc_opt, nginx_version) = nginx_data.unpack();
        request << make_pair("nginxVersion",     nginx_version);
        request << make_pair("configureOpt",     config_opt);
        request << make_pair("extraCompilerOpt", cc_opt);
    } else {
        dbgDebug(D_ORCHESTRATOR) << nginx_data.getErr();
    }

    auto cloud_metadata = details_resolver->readCloudMetadata();
    if (cloud_metadata.ok()) {
        request << make_pair("cloudAccountId", ::get<0>(cloud_metadata.unpack()));
        request << make_pair("cloudVpcId", ::get<1>(cloud_metadata.unpack()));
        request << make_pair("cloudInstanceId", ::get<2>(cloud_metadata.unpack()));
        request << make_pair("cloudInstanceLocalIp", ::get<3>(cloud_metadata.unpack()));
        request << make_pair("cloudRegion", ::get<4>(cloud_metadata.unpack()));
    } else {
        dbgDebug(D_ORCHESTRATOR) << cloud_metadata.getErr();
    }

    for (const pair<string, string> details : details_resolver->getResolvedDetails()) {
        request << details;
    }

    auto i_agent_details = Singleton::Consume<I_AgentDetails>::by<FogAuthenticator>();
    if (
        i_agent_details->getOrchestrationMode() == OrchestrationMode::HYBRID ||
        getSettingWithDefault<string>("management", "profileManagedMode") == "declarative"
    ) {
        request << make_pair("managedMode", "declarative");
    } else {
        request << make_pair("managedMode", "management");
    }

    request << make_pair("userEdition", getUserEdition());

    if (details_resolver->isReverseProxy()) {
        request << make_pair("reverse_proxy", "true");
    }

    if (details_resolver->isCloudStorageEnabled()) {
        request << make_pair("cloud_storage_service", "true");
    }

    if (details_resolver->isKernelVersion3OrHigher()) {
        request << make_pair("isKernelVersion3OrHigher", "true");
    }

    if (details_resolver->isGwNotVsx()) {
        request << make_pair("isGwNotVsx", "true");
    }

    if (details_resolver->isVersionAboveR8110()) {
        request << make_pair("isVersionAboveR8110", "true");
    }

#if defined(gaia) || defined(smb)
    if (details_resolver->compareCheckpointVersion(8100, std::greater_equal<int>())) {
        request << make_pair("isCheckpointVersionGER81", "true");
    }
    if (details_resolver->compareCheckpointVersion(8200, std::greater_equal<int>())) {
        request << make_pair("isCheckpointVersionGER82", "true");
    }
    auto maybe_vs_id = Singleton::Consume<I_Environment>::by<FogAuthenticator>()->get<string>("VS ID");
    if (maybe_vs_id.ok()) {
        request << make_pair("virtualSystemId", maybe_vs_id.unpack());
    }
#endif // gaia || smb

    dbgDebug(D_ORCHESTRATOR) << "Sending registration request to fog";
    auto request_status = Singleton::Consume<I_Messaging>::by<FogAuthenticator>()->sendSyncMessage(
        HTTPMethod::POST,
        "/agents",
        request
    );
    if (request_status.ok()) {
        dbgDebug(D_ORCHESTRATOR) << "Agent has registered successfully.";
        i_agent_details->setAgentId(request.getAgentId());
        i_agent_details->setProfileId(request.getProfileId());
        i_agent_details->setTenantId(request.getTenantId());
        i_agent_details->writeAgentDetails();

        auto orc_status = Singleton::Consume<I_OrchestrationStatus>::by<FogAuthenticator>();
        orc_status->setAgentDetails(request.getAgentId(), request.getProfileId(), request.getTenantId());
        return UserCredentials(request.getClientId(), request.getSharedSecret());
    }

    LogGen log(
        "We suggest to check that your Agent Profile is defined and enforced",
        ReportIS::Audience::SECURITY,
        ReportIS::Severity::INFO,
        ReportIS::Priority::MEDIUM,
        LogField("source", "fog_communication"),
        ReportIS::Tags::ORCHESTRATOR
    );

    return genError(
        "Failed to register agent with the Fog. " +
        request_status.getErr().getBody() +
        " " +
        request_status.getErr().toString()
    );
}

Maybe<FogAuthenticator::AccessToken>
FogAuthenticator::getAccessToken(const UserCredentials &user_credentials) const
{
    dbgDebug(D_ORCHESTRATOR) << "Requesting token from fog.";
    static const string grant_type_string = "/oauth/token?grant_type=client_credentials";
    TokenRequest request = TokenRequest();

    MessageMetadata request_token_md;
    request_token_md.insertHeader(
        "Authorization",
        buildBasicAuthHeader(user_credentials.getClientId(), user_credentials.getSharedSecret())
    );
    auto request_token_status = Singleton::Consume<I_Messaging>::by<FogAuthenticator>()->sendSyncMessage(
        HTTPMethod::POST,
        grant_type_string,
        request,
        MessageCategory::GENERIC,
        request_token_md
    );

    if (request_token_status.ok()) {
        auto data_path = getConfigurationWithDefault<string>(
            filesystem_prefix + "/data/",
            "encryptor",
            "Data files directory"
        );
        auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
        if (!orchestration_tools->writeFile(request.getAccessToken(), data_path + session_token_file_name)) {
            return genError("Failed to write new access token to file");
        }

        dbgInfo(D_ORCHESTRATOR) << "New access token was saved";
        Singleton::Consume<I_AgentDetails>::by<FogAuthenticator>()->loadAccessToken();

        return AccessToken(request.getAccessToken(), chrono::seconds(request.getExpirationTime()));
    }

    return genError("Failed to get access token.");
}

Maybe<FogAuthenticator::RegistrationData>
FogAuthenticator::getRegistrationData()
{
    if (!otp.empty()) {
        reg_data = RegistrationData(otp);
        return reg_data;
    }

    if (reg_data.ok()) {
        dbgInfo(D_ORCHESTRATOR) << "Loading registration token from cache";
        return reg_data;
    }

    auto local_env_token = getRegistrationToken();
    if (local_env_token.ok()) return local_env_token;

    return genError("Failed to load registration token from the environment.");
}

Maybe<FogAuthenticator::RegistrationData>
FogAuthenticator::getRegistrationToken()
{
    auto reg_data_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf/registration-data.json",
        "orchestration",
        "Registration data Path"
    );
    dbgTrace(D_ORCHESTRATOR) << "Getting registration token from " << reg_data_path;

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    auto raw_reg_data = orchestration_tools->readFile(reg_data_path);
    if (raw_reg_data.ok()) {
        auto decoded_reg_data = orchestration_tools->base64Decode(raw_reg_data.unpack());
        reg_data = orchestration_tools->jsonStringToObject<RegistrationData>(decoded_reg_data);

        if (reg_data.ok()) {
            dbgInfo(D_ORCHESTRATOR) << "Registration token has been loaded from: " << reg_data_path;
            return reg_data;
        }
    }

    dbgTrace(D_ORCHESTRATOR) << "Getting registration token from container environment.";
    const char *container_otp = getenv("AGENT_TOKEN");
    if (container_otp) {
        dbgInfo(D_ORCHESTRATOR) << "Registration token has been loaded from container environment";
        return RegistrationData(container_otp);
    }

    dbgTrace(D_ORCHESTRATOR) << "Getting registration token from the environment.";
    const char *env_otp = getenv("NANO_AGENT_TOKEN");
    if (env_otp) {
        dbgInfo(D_ORCHESTRATOR) << "Registration token has been loaded from the environment";
        return RegistrationData(env_otp);
    }

    return genError("No registration token in the environment");
}

void
FogAuthenticator::registerLocalAgentToFog()
{
    auto local_reg_token = getRegistrationToken();
    if (!local_reg_token.ok()) return;

    string reg_token = local_reg_token.unpack().getData();
    if (reg_token.empty()) return;

    dbgInfo(D_ORCHESTRATOR) << "Start local agent registration to the fog";

    string exec_command = "open-appsec-ctl --set-mode --online_mode --token " + reg_token;

    auto i_agent_details = Singleton::Consume<I_AgentDetails>::by<FogAuthenticator>();
    auto fog_address = i_agent_details->getFogDomain();
    if (fog_address.ok()) exec_command = exec_command + " --fog https://" + fog_address.unpack();

    auto shell_cmd = Singleton::Consume<I_ShellCmd>::by<FogAuthenticator>();
    auto maybe_cmd_output = shell_cmd->getExecOutputAndCode(
        exec_command,
        300000,
        true
    );
    if (!maybe_cmd_output.ok()){
        dbgWarning(D_ORCHESTRATOR)
            << "Failed in local agent registertion to the fog. Error: "
            << maybe_cmd_output.getErr();
        return;
    }

    if (maybe_cmd_output.unpack().second != 0) {
        dbgWarning(D_ORCHESTRATOR)
            << "Failed in local agent registertion to the fog. Error: "
            << maybe_cmd_output.unpack().first;
        return;
    }
}

bool
FogAuthenticator::saveCredentialsToFile(const UserCredentials &user_credentials) const
{
    auto data_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/data/",
        "encryptor",
        "Data files directory"
    );

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    auto cred_str = orchestration_tools->objectToJson<UserCredentials>(user_credentials);
    if (!cred_str.ok()) {
        dbgWarning(D_ORCHESTRATOR) << "Failed to parse user credentials to JSON. Error: " << cred_str.getErr();
        return false;
    }


    return orchestration_tools->writeFile(cred_str.unpack(), data_path + user_cred_file_name);
}

void
FogAuthenticator::initRestAPI()
{
    AccessTokenProvider::getAccessToken = [this] () {
        return access_token;
    };

    auto rest = Singleton::Consume<I_RestApi>::by<FogAuthenticator>();
    rest->addRestCall<FogAuthenticator::AccessTokenProvider>(RestAction::SHOW, "access-token");
}

Maybe<FogAuthenticator::UserCredentials>
FogAuthenticator::getCredentialsFromFile() const
{
    auto data_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/data/",
        "encryptor",
        "Data files directory"
    );

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    auto encrypted_cred = orchestration_tools->readFile(data_path + user_cred_file_name);
    if (!encrypted_cred.ok()) return genError(encrypted_cred.getErr());

    dbgTrace(D_ORCHESTRATOR) << "Read the user credentials from the file";

    return orchestration_tools->jsonStringToObject<UserCredentials>(encrypted_cred.unpack());
}

static string
getDeplymentType()
{
    auto deplyment_type = Singleton::Consume<I_EnvDetails>::by<FogAuthenticator>()->getEnvType();
    switch (deplyment_type) {
        case EnvType::LINUX: return "Embedded";
        case EnvType::DOCKER: return "Docker";
        case EnvType::NON_CRD_K8S:
        case EnvType::K8S: return "K8S";
        case EnvType::COUNT: break;
    }

    dbgAssertOpt(false)
        << AlertInfo(AlertTeam::CORE, "fog communication")
        << "Failed to get a legitimate deployment type: "
        << static_cast<uint>(deplyment_type);
    return "Embedded";
}

Maybe<FogAuthenticator::UserCredentials>
FogAuthenticator::getCredentials()
{
    auto maybe_credentials = getCredentialsFromFile();
    if (maybe_credentials.ok()) {
        return maybe_credentials;
    }

    dbgTrace(D_ORCHESTRATOR) << "Credentials were not not received from the file. Getting registration data.";
    auto reg_data = getRegistrationData();
    if (!reg_data.ok()) {
        return genError("Failed to load a valid registration token, Error: " + reg_data.getErr());
    }

    auto details_resolver = Singleton::Consume<I_DetailsResolver>::by<FogAuthenticator>();
    Maybe<string> name = details_resolver->getHostname();
    if (!name.ok()) return name.passErr();

    auto maybe_vs_id = Singleton::Consume<I_Environment>::by<FogAuthenticator>()->get<string>("VS ID");
    string host_name = *name;
    if (maybe_vs_id.ok()) {
        host_name.append(":");
        host_name.append(maybe_vs_id.unpack());
    }

    Maybe<string> platform = details_resolver->getPlatform();
    if (!platform.ok()) return platform.passErr();

    Maybe<string> arch = details_resolver->getArch();
    if (!arch.ok()) return arch.passErr();

    string type = getSettingWithDefault(getDeplymentType(), "orchestration", "Agent type");
    maybe_credentials = registerAgent(reg_data.unpack(), host_name, type, *platform, *arch);

    auto orc_status = Singleton::Consume<I_OrchestrationStatus>::by<FogAuthenticator>();
    orc_status->setRegistrationDetails(host_name, type, *platform, *arch);

    if (!maybe_credentials.ok()) return maybe_credentials;

    auto credentials = maybe_credentials.unpack();
    auto token_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf/registration-data.json",
        "orchestration",
        "Registration data Path"
    );

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    if (saveCredentialsToFile(credentials)) {
        if (!orchestration_tools->removeFile(token_path)) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to remove one time token file";
        }
        return credentials;
    }

    dbgWarning(D_ORCHESTRATOR) << "Failed to save credentials to file";
    Singleton::Consume<I_MainLoop>::by<FogAuthenticator>()->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        [this, credentials, token_path] ()
        {
            auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
            static uint retry_counter = 1;
            while (!saveCredentialsToFile(credentials)) {
                dbgTrace(D_ORCHESTRATOR) << "Failed to save credentials to file, retry number: " << retry_counter++;
                Singleton::Consume<I_MainLoop>::by<FogAuthenticator>()->yield(chrono::seconds(60));
            }

            if (!orchestration_tools->removeFile(token_path)) {
                dbgWarning(D_ORCHESTRATOR) << "Failed to remove one time token file";
            }
        },
        "Fog credential save to file"
    );

    return credentials;
}

string
FogAuthenticator::buildBasicAuthHeader(const string &username, const string &pass) const
{
    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    auto auth_encode = orchestration_tools->base64Encode(username + ":" + pass);
    return "Basic " + auth_encode;
}

void
FogAuthenticator::setAddressExtenesion(const std::string &extension)
{
    fog_address_ex = extension;
}


Maybe<void>
FogAuthenticator::authenticateAgent()
{
    dbgFlow(D_ORCHESTRATOR) << "Authenticating the agent";
    const int min_expiration_time = 10;
    if (!credentials.ok()) {
        dbgDebug(D_ORCHESTRATOR) << "Getting Agent credentials.";

        auto orc_status = Singleton::Consume<I_OrchestrationStatus>::by<FogAuthenticator>();
        credentials = getCredentials();
        if (!credentials.ok()) {
            dbgWarning(D_ORCHESTRATOR) << "Failed to authenticate the agent: " << credentials.getErr();
            orc_status->setFieldStatus(
                OrchestrationStatusFieldType::REGISTRATION,
                OrchestrationStatusResult::FAILED,
                "Warning: Agent/Gateway failed the authentication. Contact Check Point support."
            );
            return genError(credentials.getErr());
        }
        orc_status->setFieldStatus(
            OrchestrationStatusFieldType::REGISTRATION,
            OrchestrationStatusResult::SUCCESS
        );
    }

    auto mainloop = Singleton::Consume<I_MainLoop>::by<FogAuthenticator>();
    if (!mainloop->doesRoutineExist(routine)) {
        routine = mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::System,
            [this, min_expiration_time] ()
            {
                uint expiration_time;
                uint pre_expire_time = 0;
                do {
                    expiration_time = 20;
                    auto orc_status = Singleton::Consume<I_OrchestrationStatus>::by<FogAuthenticator>();
                    access_token = getAccessToken(credentials.unpack());
                    if (access_token.ok()) {
                        pre_expire_time = getConfigurationWithDefault<int>(
                            120,
                            "fog communication",
                            "Time (seconds) to renew token prior its expiration"
                        );
                        expiration_time = access_token.unpack().getExpiration();
                        dbgInfo(D_ORCHESTRATOR) << "New token was received, expiration time: " << expiration_time;
                        orc_status->setFieldStatus(
                            OrchestrationStatusFieldType::REGISTRATION,
                            OrchestrationStatusResult::SUCCESS
                        );
                    } else {
                        dbgWarning(D_ORCHESTRATOR)
                            << "Failed to receive access token. Error: " << access_token.getErr();
                        orc_status->setFieldStatus(
                            OrchestrationStatusFieldType::REGISTRATION,
                            OrchestrationStatusResult::FAILED,
                            "Warning: Agent/Gateway failed to receive access token. Contact Check Point support."
                        );
                    }
                    int next_session_req = max(
                        static_cast<int>(expiration_time - pre_expire_time),
                        min_expiration_time
                    );
                    dbgDebug(D_ORCHESTRATOR)
                        << "Schedule the next re-activate session token. Seconds: "
                        << next_session_req;
                    Singleton::Consume<I_MainLoop>::by<FogAuthenticator>()->yield(chrono::seconds(next_session_req));
                } while (1);
            },
            "Fog communication token periodic update",
            true
        );
        // Wait for the access token mainloop
        mainloop->yield(chrono::seconds(min_expiration_time + 1));
    }

    if (!access_token.ok()) return genError(access_token.getErr());
    return Maybe<void>();
}

void
FogAuthenticator::preload()
{
    registerExpectedConfiguration<string>("orchestration",  "Agent type");
    registerExpectedConfiguration<string>("orchestration",  "OTP Token Path");
    registerExpectedConfiguration<string>("orchestration",  "User Credentials Path");
    registerExpectedConfiguration<int>("fog communication", "Time (seconds) to renew token prior its expiration");
}

void
FogAuthenticator::loadRequiredSecurityApps()
{
    auto required_apps_file_path = getConfigurationWithDefault<string>(
        filesystem_prefix + "/conf/support-practices.txt",
        "orchestration",
        "Supported practices file path"
    );

    auto orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<FogAuthenticator>();
    if (orchestration_tools->doesFileExist(required_apps_file_path)) {
        try {
            ifstream input_stream(required_apps_file_path);
            if (!input_stream) {
                dbgDebug(D_ORCHESTRATOR)
                    <<  "Cannot open the file with required security apps"
                    <<  "File: " << required_apps_file_path;
                return;
            }

            string required_security_app;
            while (getline(input_stream, required_security_app)) {
                required_security_apps.push_back(required_security_app);
            }
            input_stream.close();

        } catch (const ifstream::failure &exception) {
            dbgWarning(D_ORCHESTRATOR)
                << "Cannot read the file with required security app lists."
                << " File: " << required_apps_file_path
                << " Error: " << exception.what();
        }
    }
}

void
FogAuthenticator::init()
{
    filesystem_prefix = getFilesystemPathConfig();
    dbgTrace(D_ORCHESTRATOR) << "Initializing Fog communication, file system path prefix: " << filesystem_prefix;
    loadRequiredSecurityApps();
    initRestAPI();
}
