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

#include "local_communication.h"
#include "config.h"

using namespace std;

USE_DEBUG_FLAG(D_ORCHESTRATOR);

void
LocalCommunication::init()
{
    filesystem_prefix = getFilesystemPathConfig();
    dbgTrace(D_ORCHESTRATOR) << "Initializing Local communication, file system path prefix: " << filesystem_prefix;
}

void
LocalCommunication::preload()
{
    registerExpectedConfiguration<string>("orchestration", "Offline manifest file path");
    registerExpectedConfiguration<string>("orchestration", "Offline settings file path");
    registerExpectedConfiguration<string>("orchestration", "Offline policy file path");
    registerExpectedConfiguration<string>("orchestration", "Offline Data file path");
}

Maybe<void>
LocalCommunication::authenticateAgent()
{
    return Maybe<void>();
}

string
LocalCommunication::getChecksum(const string &file_path)
{
    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<LocalCommunication>();
    Maybe<string> file_checksum = orchestration_tools->calculateChecksum(
        I_OrchestrationTools::SELECTED_CHECKSUM_TYPE,
        file_path
    );

    if (!file_checksum.ok()) return "";
    return file_checksum.unpack();
}

Maybe<void>
LocalCommunication::getUpdate(CheckUpdateRequest &request)
{
    auto manifest_checksum = request.getManifest();
    auto policy_checksum = request.getPolicy();
    auto settings_checksum =request.getSettings();
    auto data_checksum = request.getData();

    auto offline_manifest_checksum = getChecksum(
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_manifest.json",
            "orchestration",
            "Offline Manifest file path"
        )
    );
    auto offline_policy_checksum = getChecksum(
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_policy.json",
            "orchestration",
            "Offline Policy file path"
        )
    );
    auto offline_settings_checksum = getChecksum(
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_settings.json",
            "orchestration",
            "Offline Settings file path"
        )
    );
    auto offline_data_checksum = getChecksum(
        getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/data/offline_data.json",
            "orchestration",
            "Offline Data file path"
        )
    );

    string manifest_response = "";
    string policy_response = "";
    string settings_response = "";
    string data_response = "";

    if (!manifest_checksum.ok() || offline_manifest_checksum != manifest_checksum.unpack()) {
        manifest_response = offline_manifest_checksum;
    }

    if (!policy_checksum.ok() || offline_policy_checksum != policy_checksum.unpack()) {
        policy_response = offline_policy_checksum;
    }

    if (!settings_checksum.ok() || offline_settings_checksum != settings_checksum.unpack()) {
        settings_response = offline_settings_checksum;
    }

    if (!data_checksum.ok() || offline_data_checksum != data_checksum.unpack()) {
        data_response = offline_data_checksum;
    }

    dbgDebug(D_ORCHESTRATOR) << "Local update response, "
        << " manifest: " << (manifest_response.empty() ? "has no change," : "has new update,")
        << " policy: " << (policy_response.empty() ? "has no change," : "has new update," )
        << " settings: " << (settings_response.empty() ? "has no change" : "has new update")
        << " data: " << (data_response.empty() ? "has no change" : "has new update");

    request = CheckUpdateRequest(manifest_response, policy_response, settings_response, data_response, "", "");
    return Maybe<void>();
}

Maybe<string>
LocalCommunication::downloadAttributeFile(const GetResourceFile &resource_file)
{
    auto file_name = resource_file.getFileName();

    I_OrchestrationTools *orchestration_tools = Singleton::Consume<I_OrchestrationTools>::by<LocalCommunication>();
    if (file_name.compare("policy") == 0) {
            return orchestration_tools->readFile(getConfigurationWithDefault<string>(
                filesystem_prefix + "/conf/offline_policy.json",
                "orchestration",
                "Offline Policy file path"
            ));
        }
    if (file_name.compare("manifest") == 0) {
        return orchestration_tools->readFile(getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_manifest.json",
            "orchestration",
            "Offline Manifest file path"
        ));
    }
    if (file_name.compare("settings") == 0) {
        return orchestration_tools->readFile(getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_settings.json",
            "orchestration",
            "Offline Settings file path"
        ));
    }
    if (file_name.compare("virtualSettings") == 0) {
        return orchestration_tools->readFile(getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_virtual_manifest.json",
            "orchestration",
            "Offline virtual Manifest file path"
        ));
    }
    if (file_name.compare("virtualPolicy") == 0) {
        return orchestration_tools->readFile(getConfigurationWithDefault<string>(
            filesystem_prefix + "/conf/offline_virtual_settings.json",
            "orchestration",
            "Offline virtual Settings file path"
        ));
    }

    dbgError(D_ORCHESTRATOR) << "Unknown resource file name " << file_name;
    return genError("Failed to detect resource file name " + file_name);
}

void
LocalCommunication::setAddressExtenesion(const string &)
{
    dbgTrace(D_ORCHESTRATOR) << "Agent in offline mode, no need for address setting";
    return;
}

Maybe<void>
LocalCommunication::sendPolicyVersion(const string &, const string &) const
{
    dbgTrace(D_ORCHESTRATOR) << "Agent in offline mode, no need to send policy version";
    return Maybe<void>();
}
