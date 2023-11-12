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

#include "reverse_proxy_section.h"

#include <algorithm>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <fstream>

#include "local_policy_mgmt_gen.h"
#include "local_policy_common.h"
#include "appsec_practice_section.h"
#include "debug.h"

using namespace std;

USE_DEBUG_FLAG(D_LOCAL_POLICY);

static string conf_base_path = "/etc/cp/conf/";
static string certs_path = "/etc/certs/";
static string nginx_templates_path = "/etc/nginx/nginx-templates/";
static const string nginx_configuration_path = "openappsec-nginx-servers/";
static const string nginx_http_server_template = "nginx-http-server";
static const string nginx_ssl_server_template = "nginx-ssl-server";
static const string nginx_location_template = "nginx-location-block";

static const boost::regex host_template("<host>");
static const boost::regex private_key_template("<private-key>");
static const boost::regex certificate_template("<certificate>");
static const boost::regex location_template("<location>");
static const boost::regex upstream_template("<upstream>");
static const boost::regex host_header_template("<host-header>");
static const boost::regex dns_resolver_template("<dns-resolver>");

class ReverseProxyCertUtils
{
public:
    static std::pair<std::string, std::string> findMatchingCertificate(const std::string &host);
    static void init();

private:
    static std::vector<std::string> getFilesByExtension(const std::string &extension);
    static void untarCertificatesPackages();

    static Maybe<std::string> extractModulus(const std::string &path, const std::string &type);

    static std::unordered_map<std::string, std::string>
    calculatePublicModulus(const std::vector<std::string> &certs);

    static std::unordered_map<std::string, std::string>
    calculatePrivateModulus(const std::vector<std::string> &keys);

    static std::unordered_map<std::string, std::string> cert_key_map;
};
unordered_map<string, string> ReverseProxyCertUtils::cert_key_map;

void
RPMSettings::load(cereal::JSONInputArchive &archive_in)
{
    dbgFlow(D_LOCAL_POLICY) << "Loading RP Settings";

    parseAppsecJSONKey<string>("name", name, archive_in);
    parseAppsecJSONKey<string>("host-header", host_hdr, archive_in, "$host");
    parseAppsecJSONKey<string>("dns-resolver", dns_resolver, archive_in, "127.0.0.11");
}

const string &
RPMSettings::getName() const
{
    return name;
}

string
RPMSettings::applySettings(const std::string &server_content) const
{
    string new_server_content = ReverseProxyBuilder::replaceTemplate(server_content, host_header_template, host_hdr);
    return ReverseProxyBuilder::replaceTemplate(new_server_content, dns_resolver_template, dns_resolver);
}

void
ReverseProxyCertUtils::init()
{
    certs_path = getProfileAgentSettingWithDefault<string>("/etc/certs/", "openappsec.reverseProxy.certs");

    untarCertificatesPackages();
    cert_key_map.clear();
    auto public_modulus_map = calculatePublicModulus(getFilesByExtension(".pem"));
    auto private_modulus_map = calculatePrivateModulus(getFilesByExtension(".key"));
    for (const auto &public_modulus_entry : public_modulus_map) {
        auto public_modulus = public_modulus_entry.second;
        if (private_modulus_map.find(public_modulus) != private_modulus_map.end()) {
            dbgTrace(D_LOCAL_POLICY)
                << "Successfully parsed certificate: "
                << public_modulus_entry.first
                << " with private key: "
                << private_modulus_map[public_modulus];

            cert_key_map[public_modulus_entry.first] = private_modulus_map[public_modulus];
        }
    }
}

vector<string>
ReverseProxyCertUtils::getFilesByExtension(const string &extension)
{
    auto maybe_files = NGEN::Filesystem::getDirectoryFiles(certs_path);
    if (!maybe_files.ok()) return {};

    auto files = maybe_files.unpack();
    files.erase(
        remove_if(
            files.begin(),
            files.end(),
            [&](const string& file) { return file.length() < 4 || file.substr(file.length() - 4) != extension; }
        ),
        files.end()
    );

    for (const auto &file : files) {
        dbgTrace(D_LOCAL_POLICY) << "Found file: " << file;
    }

    return files;
}

pair<string, string>
ReverseProxyCertUtils::findMatchingCertificate(const string &host)
{
    dbgFlow(D_LOCAL_POLICY) << "Looking for a matching certificate to host: " << host;

    for (const auto &entry : cert_key_map) {
        string cert_path = entry.first;

        dbgTrace(D_LOCAL_POLICY) << "Checking match of certificate: " << cert_path;

        // Create a BIO object to read the certificate
        BIO* cert_bio = BIO_new_file(cert_path.c_str(), "rb");
        if (!cert_bio) {
            dbgWarning(D_LOCAL_POLICY) << "Could not open certificate file: " << cert_path;
            continue;
        }

        // Load the PEM-encoded public key from the file
        X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        if (!cert) {
            dbgWarning(D_LOCAL_POLICY) << "Could not parse X509 certificate file: " << cert_path;
            BIO_free(cert_bio);
            continue;
        }

        // Get the subject alternative name extension
        STACK_OF(GENERAL_NAME)* san_names = static_cast<STACK_OF(GENERAL_NAME)*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)
        );

        if (!san_names) {
            dbgWarning(D_LOCAL_POLICY) << "No Subject Alternative Name found in the certificate: " << cert_path;
            X509_free(cert);
            BIO_free(cert_bio);
            continue;
        }

        // Iterate through the SAN entries
        for (int i = 0; i < sk_GENERAL_NAME_num(san_names); ++i) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(san_names, i);
            if (name->type == GEN_DNS) {
                const char* san = reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.dNSName));

                if (X509_check_host(cert, host.c_str(), host.length(), 0, nullptr) == 1) {
                    dbgTrace(D_LOCAL_POLICY) << "Found matching certificate: " << cert_path << ", DNS name: " << san;
                    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
                    X509_free(cert);
                    BIO_free(cert_bio);
                    return {cert_path, cert_key_map[cert_path]};
                }
            }
        }
        
        dbgTrace(D_LOCAL_POLICY) << "Certificate: " << cert_path << " does not match host: " << host;

        // Clean up
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
        X509_free(cert);
        BIO_free(cert_bio);
    }

    return {};
}

Maybe<std::string>
ReverseProxyCertUtils::extractModulus(const string &path, const string &type)
{
    dbgFlow(D_LOCAL_POLICY) << "Started calculating modulus of: " << path << ", type: " << type;

    string modulus_cmd = "openssl " + type + " -noout -modulus -in " + path + "; echo $?";
    auto modulus_maybe = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(modulus_cmd);
    if (!modulus_maybe.ok()) return genError("Could not complete command, error: " + modulus_maybe.getErr());

    auto modulus_cmd_output = NGEN::Strings::removeTrailingWhitespaces(modulus_maybe.unpack());
    if (modulus_cmd_output.back() != '0') return genError("Could not extract modulus, error: " + modulus_cmd_output);

    modulus_cmd_output.pop_back();

    dbgTrace(D_LOCAL_POLICY) << "Extracted modulus for: " << path << ", " << modulus_cmd_output;

    return modulus_cmd_output;
}

unordered_map<string, string>
ReverseProxyCertUtils::calculatePublicModulus(const vector<string> &certs)
{
    dbgFlow(D_LOCAL_POLICY) << "Calculating certificates modulus";

    unordered_map<string, string> certs_modulus;
    for (const string &cert_file_name : certs) {
        string cert_path = certs_path + cert_file_name;
        auto modulus = extractModulus(cert_path, "x509");
        if (!modulus.ok()) {
            dbgWarning(D_LOCAL_POLICY) << modulus.getErr();
            continue;
        }

        certs_modulus[cert_path] = modulus.unpack();
    }

    return certs_modulus;
}

unordered_map<string, string>
ReverseProxyCertUtils::calculatePrivateModulus(const vector<string> &keys)
{
    unordered_map<string, string> key_modulus;
    for (const string &private_key_file_name : keys) {
        string private_key_path = certs_path + private_key_file_name;
        auto modulus = extractModulus(private_key_path, "rsa");
        if (!modulus.ok()) {
            dbgWarning(D_LOCAL_POLICY) << modulus.getErr();
            continue;
        }

        key_modulus[modulus.unpack()] = private_key_path;
    }

    return key_modulus;
}

void
ReverseProxyCertUtils::untarCertificatesPackages()
{
    vector<string> cert_pkgs = getFilesByExtension(".pkg");
    if (cert_pkgs.empty()) return;

    for (const auto &cert_pkg : cert_pkgs) {
        dbgTrace(D_LOCAL_POLICY) << "Untaring certificate package: " << cert_pkg;
        string untar_cmd = "tar -C " + certs_path + " -xvf " + certs_path + cert_pkg;
        auto maybe_tar_res = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(untar_cmd);
        if (!maybe_tar_res.ok()) {
            dbgWarning(D_LOCAL_POLICY) << "Untar package error: " << maybe_tar_res.getErr();
        }
    }
}

string
ReverseProxyBuilder::replaceTemplate(
    const string &content,
    const boost::regex &nginx_directive_template,
    const string &value)
{
    return NGEN::Regex::regexReplace(__FILE__, __LINE__, content, nginx_directive_template, value);
}

Maybe<string>
ReverseProxyBuilder::getTemplateContent(const string &nginx_conf_template)
{
    ifstream nginx_template_in(nginx_templates_path + nginx_conf_template);
    if (!nginx_template_in.is_open()) return genError("Could not open the " + nginx_conf_template + " template");

    string file_content((istreambuf_iterator<char>(nginx_template_in)), istreambuf_iterator<char>());
    nginx_template_in.close();

    return file_content;
}

Maybe<void>
ReverseProxyBuilder::createSSLNginxServer(const string &host, const RPMSettings &rp_settings)
{
    dbgTrace(D_LOCAL_POLICY) << "Creating SSL NGINX server: " << host;

    pair<string, string> cert_key = ReverseProxyCertUtils::findMatchingCertificate(host);
    if (cert_key.first.empty() || cert_key.second.empty()) {
        return genError("Cannot find matching certificates to host: " + host);
    }

    auto maybe_server_content = getTemplateContent(nginx_ssl_server_template);
    if (!maybe_server_content.ok()) return maybe_server_content.passErr();

    string server_content = replaceTemplate(maybe_server_content.unpack(), host_template, host);
    server_content = replaceTemplate(server_content, private_key_template, cert_key.second);
    server_content = replaceTemplate(server_content, certificate_template, cert_key.first);
    server_content = rp_settings.applySettings(server_content);

    dbgTrace(D_LOCAL_POLICY) << "NGINX SSL Server content: " << server_content;

    string conf_path = conf_base_path + nginx_configuration_path + "/443_" + host + ".conf";
    ofstream server_file(conf_path, ofstream::out | ofstream::trunc);
    if (!server_file.is_open()) {
        return genError("Could not open the output SSL NGINX configuration file: " + conf_path);
    }

    server_file << server_content;
    server_file.close();

    return {};
}

Maybe<void>
ReverseProxyBuilder::createHTTPNginxServer(const string &host, const RPMSettings &rp_settings)
{
    dbgFlow(D_LOCAL_POLICY) << "Creating HTTP NGINX server: " << host;

    auto maybe_server_content = getTemplateContent(nginx_http_server_template);
    if (!maybe_server_content.ok()) return maybe_server_content.passErr();

    string server_content = replaceTemplate(maybe_server_content.unpack(), host_template, host);
    server_content = rp_settings.applySettings(server_content);

    dbgTrace(D_LOCAL_POLICY) << "NGINX HTTP Server content: " << server_content;

    string http_server_conf_path = conf_base_path + nginx_configuration_path + "80_" + host + ".conf";
    ofstream server_file(http_server_conf_path, ofstream::out | ofstream::trunc);
    if (!server_file.is_open()) {
        return genError("Could not open the output HTTP NGINX configuration file: " + http_server_conf_path);
    }

    server_file << server_content;
    server_file.close();

    return {};
}

Maybe<void>
ReverseProxyBuilder::addNginxServerLocation(
    string location,
    const string &host,
    const ParsedRule &rule,
    const RPMSettings &rp_settings)
{
    string port = rule.rpmIsHttps() ? string("443") : string("80");
    string location_conf_path = conf_base_path + nginx_configuration_path + port + '_' + host + "_locations/";

    dbgFlow(D_LOCAL_POLICY) << "Adding a new NGINX location: " << location << " to: " << location_conf_path;
    
    NGEN::Filesystem::makeDirRecursive(location_conf_path);

    if (location.empty() || location.find_first_not_of('/') == string::npos)
    {
        location = "/";
        location_conf_path += "root_location.conf";
    }
    else
    {
        string location_conf_basename = location.substr(1, location.length() - 1) + "_location";
        replace(location_conf_basename.begin(), location_conf_basename.end(), '/', '_');
        location_conf_path += location_conf_basename + ".conf";
    }
    auto maybe_location_content = getTemplateContent(nginx_location_template);
    if (!maybe_location_content.ok()) return maybe_location_content.passErr();

    string location_content = replaceTemplate(maybe_location_content.unpack(), location_template, location);
    location_content = replaceTemplate(location_content, upstream_template, rule.rpmGetUpstream());
    location_content = rp_settings.applySettings(location_content);

    dbgTrace(D_LOCAL_POLICY) << "NGINX server location content: " << location_content;

    ofstream location_file(location_conf_path, ofstream::out | ofstream::trunc);
    if (!location_file.is_open()) {
        return genError("Could not open the output NGINX location block: " + location_conf_path);
    }

    location_file << location_content;
    location_file.close();
    
    return {};
}

Maybe<void>
ReverseProxyBuilder::createNewNginxServer(const string &host, const ParsedRule &rule, const RPMSettings &rp_settings)
{
    dbgFlow(D_LOCAL_POLICY) << "Creating a new NGINX server: " << host << ", SSL: " << rule.rpmIsHttps();

    if (rule.rpmIsHttps()) {
        auto maybe_res = ReverseProxyBuilder::createSSLNginxServer(host, rp_settings);
        if (!maybe_res.ok()) {
            return genError("Could not create an SSL NGINX server configuration: " + maybe_res.getErr());
        }
    } else {
        auto maybe_res = ReverseProxyBuilder::createHTTPNginxServer(host, rp_settings);
        if (!maybe_res.ok()) {
            return genError("Could not create an HTTP NGINX server: " + maybe_res.getErr());
        }
    }
    
    return {};
}

Maybe<void>
ReverseProxyBuilder::reloadNginx()
{
    dbgFlow(D_LOCAL_POLICY) << "Reloading NGINX...";

    auto maybe_nginx_t = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(
        "nginx -t 2>&1; echo $?"
    );
    
    if (!maybe_nginx_t.ok()){
        return genError("Could not check NGINX configuration: " + maybe_nginx_t.getErr());
    }

    string nginx_t_output = NGEN::Strings::removeTrailingWhitespaces(maybe_nginx_t.unpack());
    if (nginx_t_output.back() != '0') return genError("Invalid NGINX configuration: " + nginx_t_output);

    auto maybe_nginx_reload = Singleton::Consume<I_ShellCmd>::by<LocalPolicyMgmtGenerator>()->getExecOutput(
        "nginx -s reload 2>&1;"
    );
    
    if (!maybe_nginx_reload.ok()){
        return genError("Could not reload NGINX: " + maybe_nginx_reload.getErr());
    }

    return {};
}

void
ReverseProxyBuilder::init()
{
    conf_base_path = getConfigurationWithDefault<string>("/etc/cp/conf/", "Config Component", "configuration path");
    nginx_templates_path = getProfileAgentSettingWithDefault<string>(
        "/etc/nginx/nginx-templates/", "openappsec.reverseProxy.nginxTemplates"
    );

    NGEN::Filesystem::deleteDirectory(conf_base_path + nginx_configuration_path, true);
    NGEN::Filesystem::makeDir(conf_base_path + nginx_configuration_path);
    ReverseProxyCertUtils::init();
}
