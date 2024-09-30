#ifndef __REVERSE_PROXY_MANAGER_DEFAULTS_H__
#define __REVERSE_PROXY_MANAGER_DEFAULTS_H__

#include <string>

static const std::string product_name = getenv("DOCKER_RPM_ENABLED") ? "CloudGuard AppSec" : "AppSec Gateway";
static const std::string default_cp_cert_file = "/etc/cp/cpCert.pem";
static const std::string default_cp_key_file = "/etc/cp/cpKey.key";
static const std::string default_rpm_conf_path = "/etc/cp/conf/rpmanager/";

static const std::string default_certificate_path = "/etc/cp/rpmanager/certs";
static const std::string default_manual_certs_path = "/etc/cp/rpmanager/manualCerts/";
static const std::string default_config_path = "/etc/cp/conf/rpmanager/servers";
static const std::string default_rpm_prepare_path = "/etc/cp/conf/rpmanager/prepare/servers";

static const std::string default_nginx_log_files_path = "/var/log/nginx/";
static const std::string default_additional_files_path = "/etc/cp/conf/rpmanager/include";
static const std::string default_server_config = "additional_server_config.conf";
static const std::string default_location_config = "additional_location_config.conf";
static const std::string default_trusted_ca_suffix = "_user_ca_bundle.crt";
static const std::string default_log_files_host_path = "/var/log/nano_agent/rpmanager/nginx_log/";
static const std::string default_template_path = "/etc/cp/conf/rpmanager/nginx-template-clear";
static const std::string default_server_certificate_path = "/etc/cp/rpmanager/certs/sslCertificate_";
static const std::string default_server_certificate_key_path = "/etc/cp/rpmanager/certs/sslPrivateKey_";
static const std::string default_container_name = "cp_nginx_gaia";
static const std::string default_docker_image = "cp_nginx_gaia";
static const std::string default_nginx_config_file = "/etc/cp/conf/rpmanager/nginx.conf";
static const std::string default_prepare_nginx_config_file = "/etc/cp/conf/rpmanager/nginx_prepare.conf";
static const std::string default_global_conf_template = "/etc/cp/conf/rpmanager/nginx-conf-template";
static const std::string default_nginx_config_include_file =
    "/etc/cp/conf/rpmanager/servers/nginx_conf_include.conf";
static const std::string default_global_conf_include_template =
    "/etc/cp/conf/rpmanager/nginx-conf-include-template";
static const std::string default_global_conf_include_template_no_responses =
    "/etc/cp/conf/rpmanager/nginx-conf-include-template-no-responses";
static const std::string default_cloud_vendor_file = "/etc/cp/conf/rpmanager/cloud-vendor.json";
static const std::string default_cloud_cert_location = "/tmp/";
static const std::string default_dns_resolver_file = "/etc/resolv.conf";
static const std::string default_nginx_multi_lines_key = "nginxIncludeLines";
static const std::string default_ip = "127.0.0.1";
static const std::string default_aws_resolver_ip = "169.254.169.253";
static const std::string default_azure_resolver_ip = "168.63.129.16";
static const std::string default_syslog_socket_address = "127.0.0.1:1514";
static const std::string rpm_full_load_path = "/tmp/rpm_full_load";
static const std::string rpm_partial_load_path = "/tmp/rpm_partial_load";
static const std::string first_rpm_policy_load_path = "/tmp/first_rpm_policy_load";

static const int default_port = 5555;

#endif //__REVERSE_PROXY_MANAGER_DEFAULTS_H__
