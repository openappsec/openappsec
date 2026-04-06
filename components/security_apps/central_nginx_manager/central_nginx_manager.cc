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

#include "central_nginx_manager.h"
#include "lets_encrypt_listener.h"
#include "zone_servers_policy.h"

#include <string>
#include <vector>
#include <map>
#include <cereal/external/base64.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/string.hpp>
#include <sstream>

#include "debug.h"
#include "config.h"
#include "rest.h"
#include "log_generator.h"
#include "nginx_utils.h"
#include "agent_core_utilities.h"

using namespace std;

USE_DEBUG_FLAG(D_NGINX_MANAGER);

class CentralNginxConfig
{
public:
    void load(cereal::JSONInputArchive &ar)
    {
        try {
            string nginx_conf_base64;
            ar(cereal::make_nvp("id", file_id));
            ar(cereal::make_nvp("name", file_name));
            ar(cereal::make_nvp("data", nginx_conf_base64));
            nginx_conf_content = cereal::base64::decode(nginx_conf_base64);
            central_nginx_conf_path = getCentralNginxConfPath();
            shared_config_path = getSharedConfigPath();
            if (!nginx_conf_content.empty()) configureCentralNginx();
        } catch (const cereal::Exception &e) {
            dbgDebug(D_NGINX_MANAGER) << "Could not load Central Management Config JSON. Error: " << e.what();
            ar.setNextName(nullptr);
        }
    }

    const string & getFileId() const { return file_id; }
    const string & getFileName() const { return file_name; }
    const string & getFileContent() const { return nginx_conf_content; }

    static string
    getCentralNginxConfPath()
    {
        string central_nginx_conf_path = getProfileAgentSettingWithDefault<string>(
            string("/tmp/central_nginx.conf"),
            "centralNginxManagement.confDownloadPath"
        );
        dbgInfo(D_NGINX_MANAGER) << "Central NGINX configuration path: " << central_nginx_conf_path;

        return central_nginx_conf_path;
    }

    static string
    getSharedConfigPath()
    {
        string central_shared_conf_path = getConfigurationWithDefault<string>(
            "/etc/cp/conf",
            "Config Component",
            "configuration path"
        );
        central_shared_conf_path += "/centralNginxManager/shared/central_nginx_shared.conf";
        dbgInfo(D_NGINX_MANAGER) << "Shared NGINX configuration path: " << central_shared_conf_path;

        return central_shared_conf_path;
    }

private:
    void
    loadAttachmentModule()
    {
        string attachment_module_path = NginxUtils::getModulesPath() + "/ngx_cp_attachment_module.so";
        if (!NGEN::Filesystem::exists(attachment_module_path)) {
            dbgTrace(D_NGINX_MANAGER) << "Attachment module " << attachment_module_path << " does not exist";
            return;
        }

        string attachment_module_conf = "load_module " + attachment_module_path + ";";
        if (nginx_conf_content.find(attachment_module_conf) != string::npos) {
            dbgTrace(D_NGINX_MANAGER) << "Attachment module " << attachment_module_path << " already loaded";
            return;
        }

        nginx_conf_content = attachment_module_conf + "\n" + nginx_conf_content;
    }

    Maybe<void>
    loadSharedDirective(const string &directive)
    {
        dbgFlow(D_NGINX_MANAGER) << "Loading shared directive into the servers " << directive;

        if (!NGEN::Filesystem::copyFile(shared_config_path, shared_config_path + ".bak", true)) {
            return genError("Could not create a backup of the shared NGINX configuration file");
        }

        ifstream shared_config(shared_config_path);
        if (!shared_config.is_open()) {
            return genError("Could not open shared NGINX configuration file");
        }

        string shared_config_content((istreambuf_iterator<char>(shared_config)), istreambuf_iterator<char>());
        shared_config.close();

        if (shared_config_content.find(directive) != string::npos) {
            dbgTrace(D_NGINX_MANAGER) << "Shared directive " << directive << " already loaded";
            return {};
        }

        ofstream new_shared_config(shared_config_path, ios::app);
        if (!new_shared_config.is_open()) {
            return genError("Could not open shared NGINX configuration file");
        }

        dbgTrace(D_NGINX_MANAGER) << "Adding shared directive " << directive;
        new_shared_config << directive << "\n";
        new_shared_config.close();

        return {};
    }

    Maybe<void>
    loadSharedConfig()
    {
        dbgFlow(D_NGINX_MANAGER) << "Loading shared configuration into the servers";

        ofstream shared_config(shared_config_path);
        if (!shared_config.is_open()) {
            return genError("Could not create shared NGINX configuration file");
        }
        shared_config.close();

        string shared_config_directive = "include " + shared_config_path + ";\n";
        boost::regex server_regex("server\\s*\\{");
        nginx_conf_content = NGEN::Regex::regexReplace(
            __FILE__,
            __LINE__,
            nginx_conf_content,
            server_regex,
            "server {\n" + shared_config_directive
        );

        ofstream nginx_conf_file(central_nginx_conf_path);
        if (!nginx_conf_file.is_open()) {
            return genError("Could not open a temporary central NGINX configuration file");
        }
        nginx_conf_file << nginx_conf_content;
        nginx_conf_file.close();

        return {};
    }

    Maybe<void>
    configureSyslog()
    {
        if (!getProfileAgentSettingWithDefault<bool>(false, "centralNginxManagement.syslogEnabled")) {
            dbgTrace(D_NGINX_MANAGER) << "Syslog is disabled via settings";
            return {};
        }

        string syslog_directive = "error_log syslog:server=127.0.0.1:1514 warn;";
        auto load_shared_directive_result = loadSharedDirective(syslog_directive);
        if (!load_shared_directive_result.ok()) {
            return genError("Could not configure syslog directive, error: " + load_shared_directive_result.getErr());
        }

        return {};
    }

    Maybe<void>
    saveBaseCentralNginxConf()
    {
        ofstream central_nginx_conf_base_file(central_nginx_conf_path + ".base");
        if (!central_nginx_conf_base_file.is_open()) {
            return genError("Could not open a temporary central NGINX configuration file");
        }
        central_nginx_conf_base_file << nginx_conf_content;
        central_nginx_conf_base_file.close();

        return {};
    }

    void
    configureCentralNginx()
    {
        loadAttachmentModule();
        auto save_base_nginx_conf = saveBaseCentralNginxConf();
        if (!save_base_nginx_conf.ok()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not save base NGINX configuration. Error: "
                << save_base_nginx_conf.getErr();
            return;
        }

        string nginx_conf_content_backup = nginx_conf_content;
        auto shared_config_result = loadSharedConfig();
        if (!shared_config_result.ok()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not load shared configuration. Error: "
                << shared_config_result.getErr();
            nginx_conf_content = nginx_conf_content_backup;
            return;
        }

        auto syslog_result = configureSyslog();
        if (!syslog_result.ok()) {
            dbgWarning(D_NGINX_MANAGER) << "Could not configure syslog. Error: " << syslog_result.getErr();
        }
    }

    string file_id;
    string file_name;
    string nginx_conf_content;
    string central_nginx_conf_path;
    string shared_config_path;
};

class CentralNginxManager::Impl
{
public:
    void
    init()
    {
        dbgInfo(D_NGINX_MANAGER) << "Starting Central NGINX Manager";

        string main_nginx_conf_path = NginxUtils::getMainNginxConfPath();
        if (
            NGEN::Filesystem::exists(main_nginx_conf_path)
            && !NGEN::Filesystem::exists(main_nginx_conf_path + ".orig")
        ) {
            dbgInfo(D_NGINX_MANAGER) << "Creating a backup of the original main NGINX configuration file";
            NGEN::Filesystem::copyFile(main_nginx_conf_path, main_nginx_conf_path + ".orig", true);
        }

        i_mainloop = Singleton::Consume<I_MainLoop>::by<CentralNginxManager>();
        if (!lets_encrypt_listener.init()) {
            dbgWarning(D_NGINX_MANAGER) << "Could not start Lets Encrypt Listener, scheduling retry";
            i_mainloop->addOneTimeRoutine(
                I_MainLoop::RoutineType::System,
                [this] ()
                {
                    while(!lets_encrypt_listener.init()) {
                        dbgWarning(D_NGINX_MANAGER) << "Could not start Lets Encrypt Listener, will retry";
                        i_mainloop->yield(chrono::seconds(5));
                    }
                },
                "Lets Encrypt Listener initializer",
                false
            );
        }
    }

    void
    loadPolicy()
    {
        auto central_nginx_config = getSetting<vector<CentralNginxConfig>>("centralNginxManagement");
        if (!central_nginx_config.ok() || central_nginx_config.unpack().empty()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not load Central NGINX Management settings. Error: "
                << central_nginx_config.getErr();
            return;
        }

        auto &config = central_nginx_config.unpack().front();
        if (config.getFileContent().empty()) {
            dbgWarning(D_NGINX_MANAGER) << "Empty NGINX configuration file";
            return;
        }

        dbgTrace(D_NGINX_MANAGER)
            << "Handling Central NGINX Management settings: "
            << config.getFileId()
            << ", "
            << config.getFileName()
            << ", "
            << config.getFileContent();

        string central_nginx_conf_path = config.getCentralNginxConfPath();
        ofstream central_nginx_conf_file(central_nginx_conf_path);
        if (!central_nginx_conf_file.is_open()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not open central NGINX configuration file: "
                << central_nginx_conf_path;
            return;
        }
        central_nginx_conf_file << config.getFileContent();
        central_nginx_conf_file.close();

        auto extract_result = extractCertificates();
        if (!extract_result.ok()) {
            logError(extract_result.getErr());
            return;
        }

        auto validation_result = NginxUtils::validateNginxConf(central_nginx_conf_path);
        if (!validation_result.ok()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not validate central NGINX configuration file. Error: "
                << validation_result.getErr();
            logError(validation_result.getErr());
            return;
        }

        dbgTrace(D_NGINX_MANAGER) << "Validated central NGINX configuration file";

        auto reload_result = NginxUtils::reloadNginx(central_nginx_conf_path);
        if (!reload_result.ok()) {
            dbgWarning(D_NGINX_MANAGER)
                << "Could not reload central NGINX configuration. Error: "
                << reload_result.getErr();
            logError("Could not reload central NGINX configuration. Error: " + reload_result.getErr());
            return;
        }

        logInfo("Central NGINX configuration has been successfully reloaded");
    }

    void
    fini()
    {
        string central_nginx_base_path = CentralNginxConfig::getCentralNginxConfPath() + ".base";
        if (!NGEN::Filesystem::exists(central_nginx_base_path)) {
            dbgWarning(D_NGINX_MANAGER) << "Could not find base NGINX configuration file: " << central_nginx_base_path;
            return;
        }

        NginxUtils::reloadNginx(central_nginx_base_path);
    }

private:
    void
    logError(const string &error)
    {
        LogGen log(
            error,
            ReportIS::Level::ACTION,
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::CRITICAL,
            ReportIS::Priority::URGENT,
            ReportIS::Tags::POLICY_INSTALLATION
        );

        log.addToOrigin(LogField("eventTopic", "Central NGINX Management"));
        log << LogField("notificationId", "4165c3b1-e9bc-44c3-888b-863e204c1bfb");
        log << LogField(
            "eventRemediation",
            "Please verify your NGINX configuration and enforce policy again. "
            "Contact Check Point support if the issue persists."
        );
    }

    void
    logInfo(const string &info)
    {
        LogGen log(
            info,
            ReportIS::Level::ACTION,
            ReportIS::Audience::SECURITY,
            ReportIS::Severity::INFO,
            ReportIS::Priority::LOW,
            ReportIS::Tags::POLICY_INSTALLATION
        );

        log.addToOrigin(LogField("eventTopic", "Central NGINX Management"));
        log << LogField("notificationId", "4165c3b1-e9bc-44c3-888b-863e204c1bfb");
        log << LogField("eventRemediation", "No action required");
    }

    I_MainLoop *i_mainloop = nullptr;
    LetsEncryptListener lets_encrypt_listener;
    CentralNginxConfig central_nginx_config;

private:
    map<string, CertificateParams>
    mapCertificateParamsById(const vector<CertificatePolicy> &policies)
    {
        map<string, CertificateParams> cert_map;
        for (const auto &policy : policies) {
            const auto &params = policy.getCertificate();
            cert_map[params.getCertificateId()] = params;
            dbgDebug(D_NGINX_MANAGER)
                << "Mapped certificate ID "
                << params.getCertificateId()
                << " to its parameters.";
        }
        return cert_map;
    }

    Maybe<bool>
    extractCertificates()
    {
        vector<CNMCertificate> downloaded_certs;

        string certificates_data_path = getPolicyConfigPath("certificates", Config::ConfigFileType::Data);
        dbgDebug(D_NGINX_MANAGER) << "Path to certificates data file: " << certificates_data_path;

        if (certificates_data_path.empty()) {
            dbgInfo(D_NGINX_MANAGER) << "No certificates data file specified";
            return true;
        }

        ifstream cert_file(certificates_data_path);
        if (!cert_file.is_open()){
            dbgInfo(D_NGINX_MANAGER)
                << "Could not open "
                << certificates_data_path
                << " (file may not exist yet)";
            return true;
        }

        stringstream buffer;
        buffer << cert_file.rdbuf();
        cert_file.close();
        dbgTrace(D_NGINX_MANAGER) << "Certificates file content: " << buffer.str();

        try {
            cereal::JSONInputArchive archive_in(buffer);
            archive_in(cereal::make_nvp("certificates", downloaded_certs));
            dbgInfo(D_NGINX_MANAGER)
                << "Successfully loaded "
                << downloaded_certs.size()
                << " certificates from "
                << certificates_data_path;
        } catch (const exception &e) {
            return genError(string("Failed to parse certificates from " + certificates_data_path + ": ") + e.what());
        }

        if (downloaded_certs.empty()) {
            dbgInfo(D_NGINX_MANAGER) << "No certificates found in " << certificates_data_path;
            return true;
        }

        auto maybe_servers_config = getSetting<Servers>("rulebase", "servers");
        if (!maybe_servers_config.ok()) {
            ostringstream err_stream;
            err_stream << maybe_servers_config.getErr();
            return genError(
                string("Failed to get certificate configuration. Skipping certificate extraction. Error: ") +
                err_stream.str()
            );
        }

        const vector<CertificatePolicy> &servers_config = maybe_servers_config.unpack().getCertificates();
        dbgInfo(D_NGINX_MANAGER)
            << "Loaded "
            << servers_config.size()
            << " certificate policies from configuration";

        auto certificate_map = mapCertificateParamsById(servers_config);

        for (const auto &downloaded_cert : downloaded_certs) {
            const string &cert_id = downloaded_cert.getCertificateId();
            auto it = certificate_map.find(cert_id);
            if (it == certificate_map.end()) {
                return genError("Certificate " + cert_id + " not found in configuration.");
            }

            const CertificateParams &params = it->second;

            if (downloaded_cert.getPublicKey().empty() ||
                downloaded_cert.getPrivateKey().empty() ||
                downloaded_cert.getChain().empty()
            ) {
                return genError("Incomplete certificate data for certificate ID: " + cert_id);
            }

            //maybe should save to default locations if not provided in params
            // Write full chain (publicKey + chain) to public key location if provided
            if (!params.getPublicKeyLocation().empty()) {
                string full_chain_content = downloaded_cert.getPublicKey();
                full_chain_content += "\n" + downloaded_cert.getChain();

                if (!NGEN::Filesystem::createFileWithContent(
                    params.getPublicKeyLocation(),
                    full_chain_content,
                    true,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
                )) {
                    return genError(
                        "Failed to write publicKey for " + cert_id + " to " + params.getPublicKeyLocation()
                    );
                } else {
                    dbgInfo(D_NGINX_MANAGER)
                        << "Saved publicKey for "
                        << cert_id << " to "
                        << params.getPublicKeyLocation();
                }
            }

            // Write private key to private key location if provided
            if (!params.getPrivateKeyLocation().empty()) {
                if (!NGEN::Filesystem::createFileWithContent(
                    params.getPrivateKeyLocation(),
                    downloaded_cert.getPrivateKey(),
                    true,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH
                )) {
                    return genError(
                        "Failed to write privateKey for " + cert_id + " to " + params.getPrivateKeyLocation()
                    );
                } else {
                    dbgInfo(D_NGINX_MANAGER)
                        << "Saved privateKey for "
                        << cert_id << " to "
                        << params.getPrivateKeyLocation();
                }
            }
        }

        return true;
    }
};

CentralNginxManager::CentralNginxManager()
    :
    Component("Central NGINX Manager"),
    pimpl(make_unique<CentralNginxManager::Impl>()) {}

CentralNginxManager::~CentralNginxManager() {}

void
CentralNginxManager::init()
{
    pimpl->init();
}

void
CentralNginxManager::fini()
{
    pimpl->fini();
}

void
CentralNginxManager::preload()
{
    registerExpectedSetting<vector<CentralNginxConfig>>("centralNginxManagement");
    registerExpectedConfiguration<string>("Config Component", "configuration path");
    registerExpectedSetting<Servers>("rulebase", "servers");
    registerExpectedConfigFile("certificates", Config::ConfigFileType::Data);

    registerConfigLoadCb([this]() { pimpl->loadPolicy(); });
}
