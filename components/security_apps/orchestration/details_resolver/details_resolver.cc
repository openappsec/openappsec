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

#include "details_resolver.h"

#include <sstream>
#include <string>
#include <vector>

#include "details_resolving_handler.h"
#include "i_orchestration_tools.h"
#include "maybe_res.h"
#include "version.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

class DetailsResolver::Impl
        :
    Singleton::Provide<I_DetailsResolver>::From<DetailsResolver>
{
public:
    void init() { handler.init(); }
    Maybe<string> getHostname() override;
    Maybe<string> getPlatform() override;
    Maybe<string> getArch() override;

    map<string, string> getResolvedDetails() override;

    string getAgentVersion() override;
    bool isKernelVersion3OrHigher() override;
    bool isGwNotVsx() override;
    bool isVersionAboveR8110() override;
    bool isReverseProxy() override;
    bool isCloudStorageEnabled() override;
    Maybe<tuple<string, string, string, string, string>> readCloudMetadata() override;
    Maybe<tuple<string, string, string>> parseNginxMetadata() override;
#if defined(gaia) || defined(smb)
    bool compareCheckpointVersion(int cp_version, std::function<bool(int, int)> compare_operator) const override;
#endif // gaia || smb

private:
#if defined(gaia) || defined(smb)
    int getCheckpointVersion() const;
#endif // gaia || smb

    DetailsResolvingHanlder handler;
};

map<string, string>
DetailsResolver::Impl::getResolvedDetails()
{
    return handler.getResolvedDetails();
}

Maybe<string>
DetailsResolver::Impl::getHostname()
{
#if defined(arm32_musl) || defined(openwrt)
    auto host_name = DetailsResolvingHanlder::getCommandOutput("uname -a | awk '{print $(2)}'");
#else // not arm32_musl || openwrt
    auto host_name = DetailsResolvingHanlder::getCommandOutput("hostname");
#endif // defined(arm32_musl) || defined(openwrt)
    if (!host_name.ok()) return genError("Failed to load host name, Error: " + host_name.getErr());
    return host_name;
}

Maybe<string>
DetailsResolver::Impl::getPlatform()
{
#if defined(gaia_arm)
    return string("gaia_arm");
#elif defined(gaia)
    return string("gaia");
#elif defined(arm32_rpi)
    return string("glibc");
#elif defined(arm32_musl)
    return string("musl");
#elif defined(smb_mrv_v1)
    return string("smb_mrv_v1");
#elif defined(smb_sve_v2)
    return string("smb_sve_v2");
#elif defined(smb_thx_v3)
    return string("smb_thx_v3");
#elif defined(openwrt)
    return string("uclibc");
#elif defined(arm64_linaro)
    return string("arm64_linaro");
#elif defined(alpine)
    return string("alpine");
#elif defined(arm64_trustbox)
    return string("arm64_trustbox");
#elif defined(linux)
    return string("linux");
#else
    return genError("Failed to load platform details");
#endif
}

Maybe<string>
DetailsResolver::Impl::getArch()
{
#if defined(arm32_rpi) || defined(arm32_musl) || defined(openwrt)
    auto architecture = DetailsResolvingHanlder::getCommandOutput("uname -a | awk '{print $(NF -1) }'");
#else // not arm32_rpi || arm32_musl || openwrt
    auto architecture = DetailsResolvingHanlder::getCommandOutput("arch");
#endif // defined(arm32_rpi) || defined(arm32_musl) || defined(openwrt)
    if (!architecture.ok()) return genError("Failed to load platform architecture, Error: " + architecture.getErr());
    return architecture;
}

string
DetailsResolver::Impl::getAgentVersion()
{
    return Version::getFullVersion();
}

bool
DetailsResolver::Impl::isReverseProxy()
{
#if defined(gaia) || defined(smb)
    auto is_reverse_proxy = DetailsResolvingHanlder::getCommandOutput("cpprod_util CPPROD_IsConfigured CPwaap");
    if (is_reverse_proxy.ok() && !is_reverse_proxy.unpack().empty()) {
        return is_reverse_proxy.unpack().front() == '1';
    }
#endif
    return getenv("DOCKER_RPM_ENABLED") && getenv("DOCKER_RPM_ENABLED") == string("true");
}

bool
DetailsResolver::Impl::isCloudStorageEnabled()
{
    auto cloud_storage_mode_override = getProfileAgentSetting<bool>("agent.cloudStorage.enabled");
    if (cloud_storage_mode_override.ok()) {
        dbgDebug(D_ORCHESTRATOR) << "Received cloud-storage mode override: " << *cloud_storage_mode_override;
        return *cloud_storage_mode_override;
    }

    return getenv("CLOUD_STORAGE_ENABLED") && getenv("CLOUD_STORAGE_ENABLED") == string("true");
}

bool
DetailsResolver::Impl::isKernelVersion3OrHigher()
{
#if defined(gaia) || defined(smb)
    static const string cmd =
        "clish -c 'show version os kernel' | awk '{print $4}' "
        "| cut -d '.' -f 1 | awk -F: '{ if ( $1 >= 3 ) {print 1} else {print 0}}'";

    auto is_gogo = DetailsResolvingHanlder::getCommandOutput(cmd);
    if (is_gogo.ok() && !is_gogo.unpack().empty()) {
        return is_gogo.unpack().front() == '1';
    }
#endif
    return false;
}

bool
DetailsResolver::Impl::isGwNotVsx()
{
#if defined(gaia) || defined(smb)
    static const string is_gw_cmd = "cpprod_util FwIsFirewallModule";
    static const string is_vsx_cmd = "cpprod_util FWisVSX";
    auto is_gw = DetailsResolvingHanlder::getCommandOutput(is_gw_cmd);
    auto is_vsx = DetailsResolvingHanlder::getCommandOutput(is_vsx_cmd);
    if (is_gw.ok() && is_vsx.ok() && !is_gw.unpack().empty() && !is_vsx.unpack().empty()) {
        return is_gw.unpack().front() == '1' && is_vsx.unpack().front() == '0';
    }
#endif
    return false;
}

#if defined(gaia) || defined(smb)
bool
DetailsResolver::Impl::compareCheckpointVersion(int cp_version, std::function<bool(int, int)> compare_operator) const
{
    int curr_version = getCheckpointVersion();
    return compare_operator(curr_version, cp_version);
}

int
DetailsResolver::Impl::getCheckpointVersion() const
{
#ifdef gaia
    static const string cmd =
        "echo $CPDIR | awk '{sub(/.*-R/,\"\"); sub(/\\/.*/,\"\")}/^[0-9]*$/{$0=$0\".00\"}{sub(/\\./, \"\"); print}'";
#else // smb
    static const string cmd = "sqlcmd 'select major,minor from cpver' |"
        "awk '{if ($1 == \"major\") v += (substr($3,2) * 100);"
        " if ($1 == \"minor\") v += $3; } END { print v}'";
#endif // gaia
    auto version_out = DetailsResolvingHanlder::getCommandOutput(cmd);
    int cp_version = 0;
    if (version_out.ok()) {
        dbgTrace(D_ORCHESTRATOR) << "Identified version " << version_out.unpack();
        stringstream version_stream(version_out.unpack());
        version_stream >> cp_version;
    }
    return cp_version;
}
#endif // gaia || smb

bool
DetailsResolver::Impl::isVersionAboveR8110()
{
#if defined(gaia)
    return compareCheckpointVersion(8110, std::greater<int>());
#elif defined(smb)
    return true;
#endif
    return false;
}

static bool
isNoResponse(const string &cmd)
{
    auto res = DetailsResolvingHanlder::getCommandOutput(cmd);
    return !res.ok() || res.unpack().empty();
}

Maybe<tuple<string, string, string>>
DetailsResolver::Impl::parseNginxMetadata()
{
    auto output_path = getConfigurationWithDefault<string>(
        "/tmp/nginx_meta_data.txt",
        "orchestration",
        "Nginx metadata temp file"
    );
    const string srcipt_exe_cmd =
        getFilesystemPathConfig() +
        "/scripts/cp-nano-makefile-generator.sh -f -o " +
        output_path;

    dbgTrace(D_ORCHESTRATOR) << "Details resolver, srcipt exe cmd: " << srcipt_exe_cmd;
    if (isNoResponse("which nginx") && isNoResponse("which kong")) {
        return genError("Nginx or Kong isn't installed");
    }

    auto script_output = DetailsResolvingHanlder::getCommandOutput(srcipt_exe_cmd);
    if (!script_output.ok()) {
        return genError("Failed to generate nginx metadata, Error: " + script_output.getErr());
    }

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<DetailsResolver>();
    if (!orchestration_tools->doesFileExist(output_path)) {
        return genError("Failed to access nginx metadata file.");
    }

    vector<string> lines;
    try {
        ifstream input_stream(output_path);
        if (!input_stream) {
            return genError("Cannot open the file with nginx metadata, File: " + output_path);
        }

    string line;
        while (getline(input_stream, line)) {
            lines.push_back(line);
        }
        input_stream.close();

        orchestration_tools->removeFile(output_path);
    } catch (const ifstream::failure &exception) {
        dbgWarning(D_ORCHESTRATOR)
            << "Cannot read the file with required nginx metadata."
            << " File: " << output_path
            << " Error: " << exception.what();
    }

    if (lines.size() == 0) return genError("Failed to read nginx metadata file");
    string nginx_version;
    string config_opt;
    string cc_opt;

    for(string &line : lines) {
        if (line.size() == 0) continue;
        if (line.find("RELEASE_VERSION") != string::npos) continue;
        if (line.find("KONG_VERSION") != string::npos) continue;
        if (line.find("--with-cc=") != string::npos) continue;
        if (line.find("NGINX_VERSION") != string::npos) {
            auto eq_index = line.find("=");
            nginx_version = "nginx-" + line.substr(eq_index + 1);
            continue;
        }
        if (line.find("EXTRA_CC_OPT") != string::npos) {
            auto eq_index = line.find("=");
            cc_opt = line.substr(eq_index + 1);
            continue;
        }
        if (line.find("CONFIGURE_OPT") != string::npos) continue;
        if (line.back() == '\\') line.pop_back();
        config_opt += line;
    }
    return make_tuple(config_opt, cc_opt, nginx_version);
}

Maybe<tuple<string, string, string, string, string>>
DetailsResolver::Impl::readCloudMetadata()
{
    auto env_read_cloud_metadata = []() -> Maybe<tuple<string, string, string, string, string>> {
            string account_id = getenv("CLOUD_ACCOUNT_ID") ? getenv("CLOUD_ACCOUNT_ID") : "";
            string vpc_id = getenv("CLOUD_VPC_ID") ? getenv("CLOUD_VPC_ID") : "";
            string instance_id = getenv("CLOUD_INSTANCE_ID") ? getenv("CLOUD_INSTANCE_ID") : "";
            string instance_local_ip = getenv("CLOUD_INSTANCE_LOCAL_IP") ? getenv("CLOUD_INSTANCE_LOCAL_IP") : "";
            string region = getenv("CLOUD_REGION") ? getenv("CLOUD_REGION") : "";

        if (
            account_id.empty() ||
            vpc_id.empty() ||
            instance_id.empty() ||
            instance_local_ip.empty() ||
            region.empty()) {
            return genError("Could not read cloud metadata");
        }

        return make_tuple(account_id, vpc_id, instance_id, instance_local_ip, region);
    };

    auto cloud_metadata = env_read_cloud_metadata();
    if (!cloud_metadata.ok()) {
        const string cmd = getFilesystemPathConfig() + "/scripts/get-cloud-metadata.sh";
        dbgTrace(D_ORCHESTRATOR) << cloud_metadata.getErr() << ", trying to fetch it via cmd: " << cmd;

        auto result = DetailsResolvingHanlder::getCommandOutput(cmd);
        if (result.ok()) {
            istringstream iss(result.unpack());
            string line;
            while (getline(iss, line)) {
                size_t pos = line.find('=');
                if (pos != string::npos) {
                    string key = line.substr(0, pos);
                    string value = line.substr(pos + 1);
                    if (!key.empty() && !value.empty()) setenv(key.c_str(), value.c_str(), 1);
                }
            }
            cloud_metadata = env_read_cloud_metadata();
        } else {
            dbgWarning(D_ORCHESTRATOR) << "Could not fetch cloud metadata from cmd: " << result.getErr();
        }
    }

    if (!cloud_metadata.ok()) {
        dbgDebug(D_ORCHESTRATOR) << cloud_metadata.getErr();
        return genError("Failed to fetch cloud metadata");
    }

    dbgTrace(D_ORCHESTRATOR)
        << "Successfully fetched cloud metadata: "
        << ::get<0>(cloud_metadata.unpack()) << ", "
        << ::get<1>(cloud_metadata.unpack()) << ", "
        << ::get<2>(cloud_metadata.unpack()) << ", "
        << ::get<3>(cloud_metadata.unpack()) << ", "
        << ::get<4>(cloud_metadata.unpack());

    return cloud_metadata;
}

DetailsResolver::DetailsResolver() : Component("DetailsResolver"), pimpl(make_unique<Impl>()) {}

DetailsResolver::~DetailsResolver() {}

void
DetailsResolver::init()
{
    pimpl->init();
}

void
DetailsResolver::preload()
{
    registerExpectedConfiguration<uint32_t>("orchestration", "Details resolver time out");
}
