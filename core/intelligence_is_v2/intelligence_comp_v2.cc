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

#include "intelligence_comp_v2.h"

#include <fstream>

#include "cache.h"
#include "config.h"
#include "intelligence_invalidation.h"
#include "intelligence_is_v2/intelligence_response.h"
#include "intelligence_request.h"
#include "intelligence_server.h"

using namespace std;
using namespace chrono;
using namespace Intelligence_IS_V2;
using namespace Intelligence;

USE_DEBUG_FLAG(D_INTELLIGENCE);

static const string primary_port_setting = "local intelligence server primary port";
static const string secondary_port_setting = "local intelligence server secondary port";
static const string invalidation_uri = "/api/v2/intelligence/invalidation";
static const string registration_uri = "/api/v2/intelligence/invalidation/register";

class I_InvalidationCallBack
{
public:
    virtual void performCallBacks(const Invalidation &invalidation) const = 0;

protected:
    virtual ~I_InvalidationCallBack() {}
};

using MainAttrTypes = SerializableMultiMap<string, set<string>>;

static const map<string, Intelligence::ObjectType> object_names = {
    { "asset", Intelligence::ObjectType::ASSET },
    { "zone", Intelligence::ObjectType::ZONE },
    { "policyPackage", Intelligence::ObjectType::POLICY_PACKAGE },
    { "configuration", Intelligence::ObjectType::CONFIGURATION },
    { "session", Intelligence::ObjectType::SESSION },
    { "shortLived", Intelligence::ObjectType::SHORTLIVED }
};

class InvalidationRegistration
{
public:
    class RestCall
    {
    public:
        RestCall(const stringstream &input) : rest_body(input.str()) {}
        Maybe<string> genJson() const { return rest_body; }
        ostream & print(ostream &os) { return os << rest_body; }

    private:
        string rest_body;
    };

    void
    addInvalidation(const Invalidation &invalidation)
    {
        if (!first) stream << ',';
        stream << ' ' << invalidation.genObject();
        first = false;
    }

    RestCall
    genJson() const
    {
        stringstream res;

        res << "{ \"apiVersion\": \"v2\", \"communicationType\": \"sync\", \"callbackType\": \"invalidation\", ";
        auto details = Singleton::Consume<I_AgentDetails>::by<IntelligenceComponentV2>();
        res << "\"name\": \"" << details->getAgentId() << "\", ";
        auto rest = Singleton::Consume<I_RestApi>::by<IntelligenceComponentV2>();
        res << "\"url\": \"http://127.0.0.1:" << rest->getListeningPort() <<"/set-new-invalidation\", ";
        res << "\"dataMap\": [";
        res << stream.str();
        res << " ] }";

        return res;
    }

private:
    bool first = true;
    stringstream stream;
};

class InvalidationCallBack : Singleton::Provide<I_InvalidationCallBack>::SelfInterface
{
public:
    uint
    emplace(const Invalidation &invalidation, function<void(const Invalidation &)> cb)
    {
        dbgDebug(D_INTELLIGENCE) << "registering " << invalidation.genObject();
        do {
            ++running_id;
        } while (callbacks.find(running_id) != callbacks.end());
        callbacks.emplace(running_id, make_pair(invalidation, cb));
        return running_id;
    }

    void erase(uint id) { callbacks.erase(id); }
    bool empty() const { return callbacks.empty(); }

    InvalidationRegistration::RestCall
    getRegistration() const
    {
        InvalidationRegistration registration;

        for (auto &registed_invalidation : callbacks) {
            registration.addInvalidation(registed_invalidation.second.first);
        }

        return registration.genJson();
    }

    void
    performCallBacks(const Invalidation &invalidation) const override
    {
        dbgDebug(D_INTELLIGENCE) << "Looking for callbacks for invalidation " << invalidation.genObject();
        for (auto &registed_invalidation : callbacks) {
            dbgTrace(D_INTELLIGENCE) << "Checking against: " << registed_invalidation.second.first.genObject();
            performCallBacksImpl(invalidation, registed_invalidation.second);
        }
    }

private:
    void
    performCallBacksImpl(
        const Invalidation &actual_invalidation,
        const pair<Invalidation, function<void(const Invalidation &)>> &invalidation_and_cb
    ) const
    {
        auto &registereed_invalidation = invalidation_and_cb.first;
        auto &cb = invalidation_and_cb.second;
        if (registereed_invalidation.matches(actual_invalidation)) cb(actual_invalidation);
    }

    map<uint, pair<Invalidation, function<void(const Invalidation &)>>> callbacks;
    uint running_id = 0;
};

class RecieveInvalidation : public ServerRest
{
public:
    void
    doCall() override
    {
        Invalidation invalidation(class_name);

        if (category.isActive()) invalidation.setClassifier(ClassifierType::CATEGORY, category.get());
        if (family.isActive()) invalidation.setClassifier(ClassifierType::FAMILY, family.get());
        if (group.isActive()) invalidation.setClassifier(ClassifierType::GROUP, group.get());
        if (order.isActive()) invalidation.setClassifier(ClassifierType::ORDER, order.get());
        if (kind.isActive()) invalidation.setClassifier(ClassifierType::KIND, kind.get());

        if (mainAttributes.isActive()) {
            auto strings = getMainAttr<string>();
            for (const auto &value : strings) {
                invalidation.setStringAttr(value.first, value.second);
            }

            auto string_sets = getMainAttr<set<string>>();
            for (const auto &value : string_sets) {
                invalidation.setStringSetAttr(value.first, value.second);
            }
        }

        if (objectType.isActive()) {
            auto type = object_names.find(objectType.get());
            if (type != object_names.end()) invalidation.setObjectType(type->second);
        }

        if (sourceId.isActive()) invalidation.setSourceId(sourceId.get());

        auto i_cb = Singleton::Consume<I_InvalidationCallBack>::from<InvalidationCallBack>();
        i_cb->performCallBacks(invalidation);
    }

private:
    template <typename ValType>
    map<string, ValType>
    getMainAttr()
    {
        map<string, ValType> res;

        for (auto &vec_entry : mainAttributes.get()) {
            for (auto &attr : vec_entry.getMap<ValType>()) {
                res[attr.first] = attr.second;
            }
        }

        return res;
    }

    C2S_LABEL_PARAM(string, class_name, "class");
    C2S_OPTIONAL_PARAM(string, category);
    C2S_OPTIONAL_PARAM(string, family);
    C2S_OPTIONAL_PARAM(string, group);
    C2S_OPTIONAL_PARAM(string, order);
    C2S_OPTIONAL_PARAM(string, kind);
    C2S_OPTIONAL_PARAM(string, objectType);
    C2S_OPTIONAL_PARAM(string, sourceId);
    C2S_OPTIONAL_PARAM(vector<MainAttrTypes>, mainAttributes);
};

class IntelligenceComponentV2::Impl
        :
    Singleton::Provide<I_Intelligence_IS_V2>::From<IntelligenceComponentV2>
{
public:

    void
    init()
    {
        message = Singleton::Consume<I_Messaging>::by<IntelligenceComponentV2>();
        timer = Singleton::Consume<I_TimeGet>::by<IntelligenceComponentV2>();
        mainloop = Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();

        mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::minutes(12),
            [this] () { sendReccurringInvalidationRegistration(); },
            "Sending intelligence invalidation"
        );

        auto rest_api = Singleton::Consume<I_RestApi>::by<IntelligenceComponentV2>();
        rest_api->addRestCall<RecieveInvalidation>(RestAction::SET, "new-invalidation/source/invalidation");
    }

    bool
    sendInvalidation(const Invalidation &invalidation) const override
    {
        if (hasLocalInvalidationSupport()) {
            return sendLocalInvalidation(invalidation);
        }
        else {
            return sendGlobalInvalidation(invalidation);
        }
    }

    Maybe<uint>
    registerInvalidation(const Invalidation &invalidation, const function<void(const Invalidation &)> &cb) override
    {
        if (!invalidation.isLegalInvalidation()) return genError("Attempting to register invalid invalidation");
        if (!sendRegistration(invalidation)) return genError("Failed to register for invalidation");
        return invalidations.emplace(invalidation, cb);
    }

    void
    unregisterInvalidation(uint id) override
    {
        invalidations.erase(id);
    }

    Maybe<Response>
    getResponse(const vector<QueryRequest> &query_requests, bool is_pretty, bool is_bulk) const override
    {
        IntelligenceRequest intelligence_req(query_requests, is_pretty, is_bulk);
        if (!intelligence_req.checkAssetsLimit().ok()) return intelligence_req.checkAssetsLimit().passErr();
        if (!intelligence_req.checkMinConfidence().ok()) return intelligence_req.checkMinConfidence().passErr();
        if (intelligence_req.isPagingActivated()) {
            auto is_paging_finished = intelligence_req.isPagingFinished();
            if (is_paging_finished.ok() && *is_paging_finished) {
                return genError("Paging is activated and already finished. No need for more queries.");
            }
        }
        Sender intelligence_server(intelligence_req);
        auto response = intelligence_server.sendIntelligenceRequest();
        return response;
    }

    Maybe<Intelligence::Response>
    getResponse(const QueryRequest &query_request, bool is_pretty) const override
    {
        vector<QueryRequest> queries = {query_request};
        return getResponse(queries, is_pretty, false);
    }

private:
    bool
    hasLocalInvalidationSupport() const
    {
        auto is_supported = getProfileAgentSettingWithDefault<bool>(false, "agent.config.useLocalIntelligence");

        if (!is_supported) {
            is_supported = getProfileAgentSettingWithDefault<bool>(false, "agent.config.supportInvalidation");
        }
        return is_supported;
    }

    bool
    sendLocalInvalidation(const Invalidation &invalidation) const
    {
        dbgFlow(D_INTELLIGENCE) << "Starting local invalidation";
        return sendLocalInvalidationImpl(invalidation) || sendGlobalInvalidation(invalidation);
    }

    bool
    sendLocalInvalidationImpl(const Invalidation &invalidation) const
    {
        auto server = getSetting<string>("intelligence", "local intelligence server ip");
        if (!server.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Local intelligence server not configured";
            return false;
        }

        return
            sendLocalInvalidationImpl(invalidation, *server, primary_port_setting) ||
            sendLocalInvalidationImpl(invalidation, *server, secondary_port_setting);
    }

    bool
    sendLocalInvalidationImpl(const Invalidation &invalidation, const string &server, const string &port_setting) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending to local intelligence";

        auto port = getSetting<uint>("intelligence", port_setting);
        if (!port.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Could not resolve port for " << port_setting;
            return false;
        }

        dbgTrace(D_INTELLIGENCE)
            << "Invalidation value: "
            << (invalidation.genJson().ok() ? invalidation.genJson().unpack() : invalidation.genJson().getErr());

        MessageMetadata invalidation_req_md(server, *port);
        invalidation_req_md.insertHeaders(getHTTPHeaders());
        invalidation_req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
        return message->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            invalidation_uri,
            invalidation,
            MessageCategory::INTELLIGENCE,
            invalidation_req_md
        );
    }

    bool
    sendGlobalInvalidation(const Invalidation &invalidation) const
    {
        dbgFlow(D_INTELLIGENCE) << "Starting global invalidation";

        dbgTrace(D_INTELLIGENCE)
            << "Invalidation value: "
            << (invalidation.genJson().ok() ? invalidation.genJson().unpack() : invalidation.genJson().getErr());
        MessageMetadata global_invalidation_req_md;
        global_invalidation_req_md.insertHeaders(getHTTPHeaders());
        return message->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            invalidation_uri,
            invalidation,
            MessageCategory::INTELLIGENCE,
            global_invalidation_req_md
        );
    }

    map<string, string>
    getHTTPHeaders() const
    {
        map<string, string> headers;
        auto details = Singleton::Consume<I_AgentDetails>::by<IntelligenceComponentV2>();
        auto tenant = details->getTenantId();
        if (tenant == "") tenant = "Global";
        headers["X-Tenant-Id"] = tenant;
        auto agent = details->getAgentId();
        headers["X-Source-Id"] = agent;

        return headers;
    }

    bool
    sendRegistration(const Invalidation &invalidation) const
    {
        InvalidationRegistration registration;
        registration.addInvalidation(invalidation);

        return sendLocalRegistrationImpl(registration.genJson());
    }

    bool
    sendLocalRegistrationImpl(const InvalidationRegistration::RestCall &registration) const
    {
        auto server = getSetting<string>("intelligence", "local intelligence server ip");
        if (!server.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Local intelligence server not configured";
            return false;
        }
        return
            sendLocalRegistrationImpl(registration, *server, primary_port_setting) ||
            sendLocalRegistrationImpl(registration, *server, secondary_port_setting);
    }

    bool
    sendLocalRegistrationImpl(
        const InvalidationRegistration::RestCall &registration,
        const string &server,
        const string &port_setting
    ) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending to local registration";

        auto port = getSetting<uint>("intelligence", port_setting);
        if (!port.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Could not resolve port for " << port_setting;
            return false;
        }

        dbgTrace(D_INTELLIGENCE) << "Invalidation value: " << registration.genJson();
        MessageMetadata registration_req_md(server, *port);
        registration_req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
        return message->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            registration_uri,
            registration,
            MessageCategory::INTELLIGENCE,
            registration_req_md
        );
    }

    void
    sendReccurringInvalidationRegistration() const
    {
        if (!hasLocalInvalidationSupport() || invalidations.empty()) return;

        sendLocalRegistrationImpl(invalidations.getRegistration());
    }

    InvalidationCallBack         invalidations;
    I_Messaging               *message = nullptr;
    I_TimeGet                    *timer = nullptr;
    I_MainLoop                   *mainloop = nullptr;
};

IntelligenceComponentV2::IntelligenceComponentV2()
        :
    Component("IntelligenceComponentV2"),
    pimpl(make_unique<Impl>())
{}

IntelligenceComponentV2::~IntelligenceComponentV2() {}

void IntelligenceComponentV2::init() { pimpl->init(); }

void
IntelligenceComponentV2::preload()
{
    registerExpectedConfiguration<uint>("intelligence", "maximum request overall time");
    registerExpectedConfiguration<uint>("intelligence", "maximum request lap time");
    registerExpectedSetting<string>("intelligence", "local intelligence server ip");
    registerExpectedSetting<uint>("intelligence", primary_port_setting);
    registerExpectedSetting<uint>("intelligence", secondary_port_setting);

    registerExpectedConfigFile("agent-intelligence", Config::ConfigFileType::Policy);
}
