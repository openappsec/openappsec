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

#include "agent_details_reporter.h"

#include <string>

#include "config.h"
#include "rest.h"
#include "rest_server.h"
#include "agent_details_report.h"
#include "customized_cereal_map.h"

using namespace std;

USE_DEBUG_FLAG(D_AGENT_DETAILS);

class AttributesListener : public ServerRest
{
public:
    void
    doCall() override
    {
        auto details_reporter = Singleton::Consume<I_AgentDetailsReporter>::from<AgentDetailsReporter>();
        bool is_override_allowed = allow_override.isActive() ? allow_override.get() : false;
        res = details_reporter->addAttr(attributes.get(), is_override_allowed);
    }

    using attr_type = map<string, string>;
    C2S_PARAM(attr_type, attributes);
    C2S_OPTIONAL_PARAM(bool, allow_override);
    S2C_PARAM(bool, res);
};

class AttributesSender : public ClientRest
{
public:
    AttributesSender(const map<string, string> &attr) : attributes(attr) {}

    using attr_type = map<string, string>;
    C2S_PARAM(attr_type, attributes);
    S2C_OPTIONAL_PARAM(bool, res);
};

class AgentDetailsReporter::Impl
        :
    Singleton::Provide<I_AgentDetailsReporter>::From<AgentDetailsReporter>
{
public:
    void init();
    void fini();

    void sendReport(
        const metaDataReport &meta_data,
        const Maybe<string> &policy_version,
        const Maybe<string> &platform,
        const Maybe<string> &architecture,
        const Maybe<string> &agent_version
    ) override;

    bool addAttr(const string &key, const string &val, bool allow_override = false) override;
    bool addAttr(const map<string, string> &attr, bool allow_override = false) override;
    void deleteAttr(const string &key) override;

    bool sendAttributes() override;

private:
    template <typename Fstream, typename Archive>
    class AttrSerializer
    {
    public:
        AttrSerializer(map<string, string> &attr, const string &op) : attributes(attr), operation(op) {}
        ~AttrSerializer() { handleAttrPersistence(); }

    private:
        void
        handleAttrPersistence()
        {
            dbgFlow(D_AGENT_DETAILS);
            string Persistence_file_path = getConfigurationWithDefault<string>(
                getFilesystemPathConfig() + "/conf/reportedAttrBackup.json",
                "Agent details",
                "Attributes persistence file path"
            );
            dbgTrace(D_AGENT_DETAILS) << "Persistence file path: " << Persistence_file_path;

            Fstream backup_file(Persistence_file_path);
            if (!backup_file.is_open()) {
                dbgWarning(D_AGENT_DETAILS)
                    << "Failed to open attributes Persistence file. Operation: "
                    << operation
                    << ", Path "
                    << Persistence_file_path;
                return;
            }

            try {
                Archive ar(backup_file);
                ar(cereal::make_nvp("attributes", attributes));
            } catch (const exception &e) {
                dbgWarning(D_AGENT_DETAILS)
                    << "Failed to serialize attributes. Operation: "
                    << operation
                    << ", Error: "
                    << e.what();
                return;
            }

            dbgInfo(D_AGENT_DETAILS)
                << "Successfully handled attributes persistence. Operation: "
                << operation
                << ", Path "
                << Persistence_file_path;
        }

        map<string, string> &attributes;
        const string &operation;
    };

    map<string, string> persistant_attributes;
    map<string, string> new_attributes;
    map<string, string> attributes;

    I_Messaging *messaging = nullptr;
    bool is_server;
};

metaDataReport &
metaDataReport::operator<<(const pair<string, string> &data)
{
    agent_details.insert(data);
    return *this;
}

bool
metaDataReport::operator==(const metaDataReport &other) const
{
    return agent_details == other.agent_details;
}

void
metaDataReport::serialize(cereal::JSONOutputArchive &out_ar) const
{
    for (auto &data : agent_details) {
        out_ar(cereal::make_nvp(data.first, data.second));
    }
}

bool
AgentDetailsReporter::Impl::addAttr(const string &key, const string &val, bool allow_override)
{
    dbgDebug(D_AGENT_DETAILS)
        << "Trying to add new attribute. Key: "
        << key
        << ", Value: "
        << val
        << " Should allow override: "
        << (allow_override ? "true" : "false");

    if (!allow_override) {
        if (attributes.count(key) > 0 || new_attributes.count(key) > 0) {
            dbgWarning(D_AGENT_DETAILS)
                << "Cannot override an existing value with a new one. Existing Value: "
                << (attributes.count(key) > 0 ? attributes[key] : new_attributes[key]);
            return false;
        }
    }

    if (persistant_attributes[key] == val) {
        dbgDebug(D_AGENT_DETAILS) << "Attribute " << key << " did not change. Value: " << val;
        return true;
    }
    new_attributes[key] = val;
    persistant_attributes[key] = val;
    dbgDebug(D_AGENT_DETAILS) << "Successfully added new attribute";

    return true;
}

bool
AgentDetailsReporter::Impl::addAttr(const map<string, string> &attr, bool allow_override)
{
    dbgFlow(D_AGENT_DETAILS);
    bool ret = true;
    for (const auto &single_attr : attr) {
        if (!addAttr(single_attr.first, single_attr.second, allow_override)) ret = false;
    }

    dbgDebug(D_AGENT_DETAILS) << "Finished adding of new attributes map. Res: " << (ret ? "Success" : "Failure");
    return ret;
}

void
AgentDetailsReporter::Impl::deleteAttr(const string &key)
{
    dbgDebug(D_AGENT_DETAILS) << "Deleting existing attributes. Key: " << key;
    attributes.erase(key);
    new_attributes.erase(key);
    persistant_attributes.erase(key);
}

bool
AgentDetailsReporter::Impl::sendAttributes()
{
    dbgDebug(D_AGENT_DETAILS) << "Trying to send attributes";

    if (new_attributes.empty()) {
        dbgDebug(D_AGENT_DETAILS) << "Skipping current attempt since no new attributes were added";
        return true;
    }

    for (const auto &new_attr : new_attributes) {
        attributes[new_attr.first] = new_attr.second;
    }


    AttributesSender attr_to_send(attributes);
    if (is_server) {
        AttrSerializer<ofstream, cereal::JSONOutputArchive>(attributes, "save");

        messaging->sendObjectWithPersistence(attr_to_send, I_Messaging::Method::PATCH, "/agents");
        dbgDebug(D_AGENT_DETAILS) << "Triggered persistent message request with attributes to the Fog";
        new_attributes.clear();
        return true;
    }

    for (uint retry = 3; retry > 0; retry--) {
        ::Flags<MessageConnConfig> conn_flags;
        conn_flags.setFlag(MessageConnConfig::ONE_TIME_CONN);
        bool is_success = messaging->sendObject(
            attr_to_send,
            I_Messaging::Method::POST,
            "127.0.0.1",
            7777, // primary Orchestrator's port
            conn_flags,
            "add-agent-details-attr"
        );
        if (!is_success) {
            is_success = messaging->sendObject(
                attr_to_send,
                I_Messaging::Method::POST,
                "127.0.0.1",
                7778, // secondary Orchestrator's port
                conn_flags,
                "add-agent-details-attr"
            );
        }

        if (is_success) {
            dbgDebug(D_AGENT_DETAILS) << "Successfully sent attributes to the Orchestrator";
            new_attributes.clear();
            return true;
        }

        dbgDebug(D_AGENT_DETAILS) << "Could not send attributes to the Orchestrator. Retries left: " << (retry - 1);
        Singleton::Consume<I_MainLoop>::by<AgentDetailsReporter>()->yield(chrono::milliseconds(500));
    }

    dbgWarning(D_AGENT_DETAILS) << "Completely failed to send attributes to the Orchestrator";

    return false;
}

class additionalMetaDataRest : public ClientRest
{
public:
    additionalMetaDataRest(const metaDataReport &_additionalMetaData)
            :
        additionalMetaData(_additionalMetaData)
    {
    }

    void
    setPolicyVersion(const string &policy_version)
    {
        policyVersion = policy_version;
    }

    void
    setPlatform(const string &_platform)
    {
        platform = _platform;
    }

    void
    setArchitecture(const string &_architecture)
    {
        architecture = _architecture;
    }

    void
    setAgentVersion(const string &agent_version)
    {
        agentVersion = agent_version;
    }

    void
    setAdditionalAttributes(const map<string, string> &attr)
    {
        attributes = attr;
    }

private:
    C2S_PARAM(metaDataReport, additionalMetaData);
    C2S_OPTIONAL_PARAM(string, agentVersion);
    C2S_OPTIONAL_PARAM(string, policyVersion);
    C2S_OPTIONAL_PARAM(string, platform);
    C2S_OPTIONAL_PARAM(string, architecture);

    using attr_type = map<string, string>;
    C2S_OPTIONAL_PARAM(attr_type, attributes);
};

void
AgentDetailsReporter::Impl::init()
{
    messaging = Singleton::Consume<I_Messaging>::by<AgentDetailsReporter>();
    auto is_orchestrator = Singleton::Consume<I_Environment>::by<AgentDetailsReporter>()->get<bool>("Is Orchestrator");
    is_server = is_orchestrator.ok() && *is_orchestrator;

    if (is_server) {
        I_RestApi *rest = Singleton::Consume<I_RestApi>::by<AgentDetailsReporter>();
        rest->addRestCall<AttributesListener>(RestAction::ADD, "agent-details-attr");
        AttrSerializer<ifstream, cereal::JSONInputArchive>(new_attributes, "load");
    }

    Singleton::Consume<I_MainLoop>::by<AgentDetailsReporter>()->addRecurringRoutine(
        I_MainLoop::RoutineType::Offline,
        chrono::seconds(30),
        [this]()
        {
            if (!sendAttributes()) {
                dbgWarning(D_AGENT_DETAILS) << "Failed to send periodic agent details attributes map";
            } else {
                dbgDebug(D_AGENT_DETAILS) << "Successfully sent periodic agent details attributes map";
            };
        },
        "Report agent details attributes",
        false
    );
}

void
AgentDetailsReporter::Impl::fini()
{
    if (!new_attributes.empty()) {
        for (const auto &new_attr : new_attributes) {
            attributes[new_attr.first] = new_attr.second;
        }
    }

    if (is_server) {
        AttrSerializer<ofstream, cereal::JSONOutputArchive>(attributes, "save");
    }
}

void
AgentDetailsReporter::Impl::sendReport(
    const metaDataReport &meta_data,
    const Maybe<string> &policy_version,
    const Maybe<string> &platform,
    const Maybe<string> &architecture,
    const Maybe<string> &agent_version)
{
    if (!is_server) return;

    additionalMetaDataRest additional_metadata(meta_data);

    if (policy_version.ok()) additional_metadata.setPolicyVersion(*policy_version);
    if (platform.ok()) additional_metadata.setPlatform(*platform);
    if (architecture.ok()) additional_metadata.setArchitecture(*architecture);
    if (agent_version.ok()) additional_metadata.setAgentVersion(*agent_version);

    if (!new_attributes.empty()) {
        for (const auto &new_attr : new_attributes) {
            attributes[new_attr.first] = new_attr.second;
        }
        AttrSerializer<ofstream, cereal::JSONOutputArchive>(attributes, "save");
        new_attributes.clear();
        additional_metadata.setAdditionalAttributes(attributes);
    }

    messaging->sendObjectWithPersistence(additional_metadata, I_Messaging::Method::PATCH, "/agents");
}

AgentDetailsReporter::AgentDetailsReporter()
        :
    Component("AgentDetailsReporter"),
    pimpl(make_unique<Impl>())
{
}

AgentDetailsReporter::~AgentDetailsReporter() {}

void AgentDetailsReporter::init() { pimpl->init(); }
void AgentDetailsReporter::fini() { pimpl->fini(); }

void
AgentDetailsReporter::preload()
{
    registerExpectedConfiguration<string>("Agent details", "Attributes persistence file path");
}
