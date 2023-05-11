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

#include "downloader.h"

#include "i_orchestration_tools.h"
#include "singleton.h"
#include "http_client.h"
#include "debug.h"
#include "config.h"
#include "rest.h"
#include "cereal/external/rapidjson/document.h"

#include "customized_cereal_map.h"
#include "cereal/archives/json.hpp"
#include "cereal/types/vector.hpp"
#include "cereal/types/string.hpp"

#include <fstream>

using namespace std;
using namespace rapidjson;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

// LCOV_EXCL_START Reason: WA for NSaaS upgrade
class TenantProfileMap
{
public:
    void
    load(const string &raw_value)
    {
        vector<string> tenants_and_profiles;
        {
            stringstream string_stream(raw_value);
            cereal::JSONInputArchive archive(string_stream);
            cereal::load(archive, tenants_and_profiles);
        }
        for (const auto &tenant_profile_pair : tenants_and_profiles) {
            value.push_back(tenant_profile_pair);
        }
    }

    const vector<string> & getValue() const { return value; }
private:
    vector<string> value;
};

// LCOV_EXCL_STOP

class Downloader::Impl : Singleton::Provide<I_Downloader>::From<Downloader>
{
public:
    void init();

    Maybe<string> downloadFileFromFog(
        const string &checksum,
        Package::ChecksumTypes checksum_type,
        const GetResourceFile &resourse_file
    ) const override;

    Maybe<map<pair<string, string>, string>> downloadVirtualFileFromFog(
        const GetResourceFile &resourse_file,
        Package::ChecksumTypes checksum_type
    ) const override;

    Maybe<string> downloadFileFromURL(
        const string &url,
        const string &checksum,
        Package::ChecksumTypes checksum_type,
        const string &service_name
    ) const override;

    void createTenantProfileMap();
    string getProfileFromMap(const string &tenant_id) const override;

private:
    Maybe<string> downloadFileFromFogByHTTP(
        const GetResourceFile &resourse_file,
        const string &file_name
    ) const;

    Maybe<string> validateChecksum(
        const string &checksum,
        Package::ChecksumTypes checksum_type,
        Maybe<string> &file_path
    ) const;

    Maybe<string> getFileFromExternalURL(
        const URLParser &url,
        const string &file_name,
        bool auth_required
    ) const;
    Maybe<string> getFileFromLocal(const string &local_file_path, const string &file_name) const;
    Maybe<string> getFileFromURL(const URLParser &url, const string &file_name, bool auth_required) const;

    tuple<string, string> splitQuery(const string &query) const;
    string vectorToPath(const vector<string> &vec) const;
    string dir_path;
    map<string, string> tenant_profile_map;
};

void
Downloader::Impl::init()
{
    dir_path = getConfigurationWithDefault<string>(
        "/tmp/orchestration_downloads",
        "orchestration",
        "Default file download path"
    );

    Singleton::Consume<I_OrchestrationTools>::by<Downloader>()->createDirectory(dir_path);
}

Maybe<string>
Downloader::Impl::downloadFileFromFog(
    const string &checksum,
    Package::ChecksumTypes checksum_type,
    const GetResourceFile &resourse_file) const
{
    auto file_path = downloadFileFromFogByHTTP(resourse_file, resourse_file.getFileName() + ".download");

    if (!file_path.ok()) {
        return file_path;
    }

    auto checksum_validation = validateChecksum(checksum, checksum_type, file_path);
    if (!checksum_validation.ok()) return checksum_validation;

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
    if (!orchestration_tools->isNonEmptyFile(file_path.unpack())) {
        return genError("Failed to download file " + resourse_file.getFileName());
    }

    return file_path;
}

void
Downloader::Impl::createTenantProfileMap()
{
    dbgFlow(D_ORCHESTRATOR) << "Creating a tenant-profile map from the agent settings";
    tenant_profile_map.clear();
    auto maybe_tenant_profile_map = getProfileAgentSetting<TenantProfileMap>("TenantProfileMap");
    if (maybe_tenant_profile_map.ok()) {
        dbgTrace(D_ORCHESTRATOR) << "Managed to read the TenantProfileMap agent settings";
        TenantProfileMap tpm = maybe_tenant_profile_map.unpack();
        for (const string &str : tpm.getValue()) {
            string delimiter = ":";
            string tenant = str.substr(0, str.find(delimiter));
            string profile = str.substr(str.find(delimiter) + 1);
            dbgTrace(D_ORCHESTRATOR)
                << "Loading into the map. Tenant: "
                << tenant
                << " Profile: "
                << profile;
            tenant_profile_map[tenant] = profile;
        }
    } else {
        dbgTrace(D_ORCHESTRATOR) << "Couldn't load the TenantProfileMap agent settings";
    }
}

// LCOV_EXCL_START Reason: NSaaS old profiles support
string
Downloader::Impl::getProfileFromMap(const string &tenant_id) const
{
    if (tenant_profile_map.find(tenant_id) == tenant_profile_map.end()) {
        return "";
    }
    return tenant_profile_map.at(tenant_id);
}
// LCOV_EXCL_STOP

Maybe<map<pair<string, string>, string>>
Downloader::Impl::downloadVirtualFileFromFog(
    const GetResourceFile &resourse_file,
    Package::ChecksumTypes) const
{
    static const string tenand_id_key  = "tenantId";
    static const string profile_id_key = "profileId";
    static const string policy_key     = "policy";
    static const string settings_key   = "settings";
    static const string tenants_key    = "tenants";
    static const string error_text     = "error";

    map<pair<string, string>, string> res;
    I_UpdateCommunication *update_communication = Singleton::Consume<I_UpdateCommunication>::by<Downloader>();
    auto downloaded_data = update_communication->downloadAttributeFile(resourse_file);
    if (!downloaded_data.ok()) return downloaded_data.passErr();

    Document document;
    document.Parse(downloaded_data.unpack().c_str());
    if (document.HasParseError()) {
        dbgWarning(D_ORCHESTRATOR) << "JSON file is not valid";
        return genError("JSON file is not valid.");
    }
    const Value &tenants_data = document[tenants_key.c_str()];
    for (Value::ConstValueIterator itr = tenants_data.Begin(); itr != tenants_data.End(); ++itr) {

        auto tenant_id_obj = itr->FindMember(tenand_id_key.c_str());
        if (tenant_id_obj == itr->MemberEnd()) continue;

        string tenant_id =  tenant_id_obj->value.GetString();

        Value::ConstMemberIterator artifact_data = itr->FindMember(policy_key.c_str());
        if (artifact_data == itr->MemberEnd()) artifact_data = itr->FindMember(settings_key.c_str());

        if (artifact_data != itr->MemberEnd()) {
            auto profile_id_obj = itr->FindMember(profile_id_key.c_str());
            string profile_id;
            if (profile_id_obj == itr->MemberEnd()) {
                if (tenant_profile_map.count(tenant_id)) {
                    dbgWarning(D_ORCHESTRATOR)
                        << "Forcing profile ID to be "
                        << getProfileFromMap(tenant_id);
                    profile_id = getProfileFromMap(tenant_id);
                } else {
                    dbgWarning(D_ORCHESTRATOR) << "Couldn't force profile ID";
                    continue;
                }
            }

            if (profile_id.empty()) profile_id = profile_id_obj->value.GetString();
            dbgTrace(D_ORCHESTRATOR) << "Found a profile ID " << profile_id;

            string file_path =
                dir_path + "/" + resourse_file.getFileName() + "_" +
                tenant_id + "_profile_" + profile_id + ".download";

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            artifact_data->value.Accept(writer);

            I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
            if (orchestration_tools->writeFile(buffer.GetString(), file_path)) {
                res.insert({{tenant_id, profile_id}, file_path});
            }

            orchestration_tools->fillKeyInJson(file_path, "profileID", profile_id);
            orchestration_tools->fillKeyInJson(file_path, "tenantID", tenant_id);
            continue;
        }

        Value::ConstMemberIterator error_data = itr->FindMember(error_text.c_str());
        if (error_data != itr->MemberEnd()) {
            dbgDebug(D_ORCHESTRATOR)
                << "Failed to download artifact"
                << ", Tenant ID:  " << tenant_id
                << ", Error message: " << error_data->value.FindMember("message")->value.GetString()
                << ", Error ID: " << error_data->value.FindMember("messageId")->value.GetString();
            continue;
        }
    }
    return res;
}

Maybe<string>
Downloader::Impl::downloadFileFromURL(
    const string &url,
    const string &checksum,
    Package::ChecksumTypes checksum_type,
    const string &service_name) const
{
    dbgDebug(D_ORCHESTRATOR) << "Download file. URL: " << url;

    string new_url = url;
    bool auth_required = false;
    auto custom_url = getConfiguration<string>("orchestration", "Custom download url");
    if (custom_url.ok()) {
        auto resource_index = url.find_last_of("/");
        string error_msg = "Failed to parse custom URL. ";
        if (resource_index == string::npos) {
            return genError(error_msg + "URL: " + url);
        }
        new_url = custom_url.unpack();
        if (new_url.empty()) {
            return genError(error_msg + "URL is empty");
        }
        if (new_url.back() == '/') {
            new_url = new_url.substr(0, new_url.size() - 1);
        }
        new_url.append(url.substr(resource_index));
    }
    // Workaround - only in staging we need to add the auth header
    static const string jwt_word = "<JWT>";
    if (new_url.find(jwt_word) != string::npos) {
        new_url = new_url.substr(jwt_word.length());
        auth_required = true;
    }

    URLParser parsed_url(new_url);
    Maybe<string> base_url = parsed_url.getBaseURL();
    if (!base_url.ok()) return base_url;
    Maybe<string> file_path = genError("Empty path");
    string file_name = service_name + ".download";
    if (parsed_url.getProtocol() == URLProtocol::LOCAL_FILE) {
        file_path = getFileFromLocal(base_url.unpack(), file_name);
    } else {
        file_path = getFileFromExternalURL(parsed_url, file_name, auth_required);
    }

    if (!file_path.ok()) {
        return file_path;
    }

    auto checksum_validation = validateChecksum(checksum, checksum_type, file_path);
    if (!checksum_validation.ok()) return checksum_validation;

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
    if (!orchestration_tools->isNonEmptyFile(file_path.unpack())) {
        return genError("Failed to download file. URL: " + parsed_url.toString());
    }

    return file_path;
}

Maybe<string>
Downloader::Impl::validateChecksum(
    const string &checksum,
    Package::ChecksumTypes checksum_type,
    Maybe<string> &file_path) const
{
    if (file_path.ok()) {
        I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
        Maybe<string> file_checksum = orchestration_tools->calculateChecksum(checksum_type, file_path.unpack());
        if (!file_checksum.ok() || checksum != file_checksum.unpack()) {
            orchestration_tools->removeFile(file_path.unpack());
            if (!file_checksum.ok()) {
                return genError("Failed to calculate file checksum, with error: " + file_checksum.getErr());
            }
            return genError(
                "The checksum calculation is not as the expected, " +
                checksum + " != " + file_checksum.unpack()
            );
        }
    }
    return file_path;
}

Maybe<string>
Downloader::Impl::downloadFileFromFogByHTTP(const GetResourceFile &resourse_file, const string &file_name) const
{
    string file_path = dir_path + "/" + file_name;

    dbgInfo(D_ORCHESTRATOR) << "Downloading file from fog. File: " << resourse_file.getFileName();

    I_UpdateCommunication *update_communication = Singleton::Consume<I_UpdateCommunication>::by<Downloader>();
    auto downloaded_file = update_communication->downloadAttributeFile(resourse_file);
    if (!downloaded_file.ok()) return genError(downloaded_file.getErr());
    dbgInfo(D_ORCHESTRATOR) << "Download completed. File: " << resourse_file.getFileName();

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
    if (orchestration_tools->writeFile(downloaded_file.unpack(), file_path)) return file_path;
    return genError("Failed to write the attribute file. File: " + file_name);
}

Maybe<string>
Downloader::Impl::getFileFromLocal(const string &local_file_path, const string &file_name) const
{
    string file_path = dir_path + "/" + file_name;
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<Downloader>();
    if (!orchestration_tools->copyFile(local_file_path, file_path)) {
        return genError("Get file from local failed. File: " + local_file_path);
    }

    return file_path;
}

// LCOV_EXCL_START Reason: Depends on real download server.
Maybe<string>
Downloader::Impl::getFileFromURL(const URLParser &url, const string &file_path, bool auth_required) const
{
    ofstream outFile(file_path, ofstream::out | ofstream::binary);
    HTTPClient http_client;
    dbgInfo(D_ORCHESTRATOR) << "Downloading file. URL: " << url;
    auto get_file_response = http_client.getFile(url, outFile, auth_required);
    if (!get_file_response.ok()) {
        Maybe<string> error = genError("Failed to download file from " + url.getBaseURL().unpack() +
                    ". Error: " + get_file_response.getErr());
        dbgWarning(D_ORCHESTRATOR) << "Download failed";
        return error;
    }
    outFile.close();
    dbgInfo(D_ORCHESTRATOR) << "Download completed. URL: " << url;
    return file_path;
}

Maybe<string>
Downloader::Impl::getFileFromExternalURL(
    const URLParser &parsed_url,
    const string &file_name,
    bool auth_required
) const
{
    string file_path = dir_path + "/" + file_name;
    auto base_url = parsed_url.getBaseURL().unpack();

    string query_path;
    string query_file;
    tie(query_path, query_file) = splitQuery(parsed_url.getQuery());

    auto try_dirs = getConfigurationWithDefault<bool>(
        false,
        "orchestration",
        "Add tenant suffix"
    );
    if (try_dirs) {
        vector<string> sub_path;
        auto agent_details = Singleton::Consume<I_AgentDetails>::by<Downloader>();
        auto tenant_id = agent_details->getTenantId();
        if (!tenant_id.empty()) {
            sub_path.push_back(tenant_id);
            auto profile_id = agent_details->getProfileId();
            if (!profile_id.empty()) {
                sub_path.push_back(profile_id);
                auto agent_id = agent_details->getAgentId();
                if(!agent_id.empty()) {
                    sub_path.push_back(agent_id);
                }
            }
        }

        URLParser currentUrl = parsed_url;
        while (!sub_path.empty()) {
            currentUrl.setQuery(query_path + vectorToPath(sub_path) + "/" + query_file);
            if (getFileFromURL(currentUrl, file_path, auth_required).ok()) return file_path;
            sub_path.pop_back();
        }
    }

    return getFileFromURL(parsed_url, file_path, auth_required);
}

tuple<string, string>
Downloader::Impl::splitQuery(const string &query) const
{
    size_t index = query.find_last_of("/");
    if (index == string::npos) return make_tuple(string(), query);
    return make_tuple(query.substr(0, index), query.substr(index + 1));
}

string
Downloader::Impl::vectorToPath(const vector<string> &vec) const
{
    string s;
    for (const auto &piece : vec) { s += ("/" + piece); }
    return s;
}

Downloader::Downloader() : Component("Downloader"), pimpl(make_unique<Impl>()) {}

Downloader::~Downloader() {}

void
Downloader::init()
{
    pimpl->init();
}

void
Downloader::preload()
{
    registerExpectedConfiguration<string>("orchestration", "Custom download url");
    registerExpectedConfiguration<string>("orchestration", "Default file download path");
    registerExpectedConfiguration<string>("orchestration", "Self signed certificates acceptable");
    registerExpectedConfiguration<bool>("orchestration", "Add tenant suffix");
    registerConfigLoadCb([this]() { pimpl->createTenantProfileMap(); });
}
