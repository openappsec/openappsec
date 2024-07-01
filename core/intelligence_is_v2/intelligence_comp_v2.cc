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

using namespace std;
using namespace chrono;
using namespace Intelligence_IS_V2;
using namespace Intelligence;

USE_DEBUG_FLAG(D_INTELLIGENCE);

static const string primary_port_setting = "local intelligence server primary port";
static const string secondary_port_setting = "local intelligence server secondary port";
static const string invalidation_uri = "/api/v2/intelligence/invalidation";
static const string registration_uri = "/api/v2/intelligence/invalidation/register";
static const string query_uri = "/api/v2/intelligence/assets/query";
static const string queries_uri = "/api/v2/intelligence/assets/queries";

class I_InvalidationCallBack
{
public:
    virtual void performCallBacks(const Invalidation &invalidation, const string &registration_id) const = 0;

protected:
    virtual ~I_InvalidationCallBack() {}
};

static const map<string, Intelligence::ObjectType> object_names = {
    { "asset", Intelligence::ObjectType::ASSET },
    { "zone", Intelligence::ObjectType::ZONE },
    { "policyPackage", Intelligence::ObjectType::POLICY_PACKAGE },
    { "configuration", Intelligence::ObjectType::CONFIGURATION },
    { "session", Intelligence::ObjectType::SESSION },
    { "shortLived", Intelligence::ObjectType::SHORTLIVED }
};

static const map<string, Intelligence::InvalidationType> invalidation_type_names = {
    { "add", Intelligence::InvalidationType::ADD },
    { "delete", Intelligence::InvalidationType::DELETE },
    { "update", Intelligence::InvalidationType::UPDATE }
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
        auto invalidation_reg_id = invalidation.getRegistrationID();
        if (invalidation_reg_id.ok()) registration_id_to_cb[*invalidation_reg_id] = cb;
        callbacks.emplace(running_id, make_pair(invalidation, cb));
        return running_id;
    }

    void
    erase(uint id)
    {
        auto actual_invalidation = callbacks.find(id);
        if (actual_invalidation == callbacks.end()) return;
        auto invalidation_reg_id = actual_invalidation->second.first.getRegistrationID();
        if (invalidation_reg_id.ok()) registration_id_to_cb.erase(*invalidation_reg_id);
        callbacks.erase(id);
    }

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
    performCallBacks(const Invalidation &invalidation, const string &registration_id) const override
    {
        dbgDebug(D_INTELLIGENCE) << "Looking for callbacks for invalidation " << invalidation.genObject();
        if (registration_id != "") {
            auto invalidation_cb = registration_id_to_cb.find(registration_id);
            if (invalidation_cb != registration_id_to_cb.end()) return invalidation_cb->second(invalidation);
        }
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
        if (!registereed_invalidation.matches(actual_invalidation)) return;
        cb(actual_invalidation);
    }

    map<uint, pair<Invalidation, function<void(const Invalidation &)>>> callbacks;
    map<string, function<void(const Invalidation &)>> registration_id_to_cb;
    uint running_id = 0;
};

class ReceiveInvalidation : public ServerRest
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
            for (auto &vec_entry : mainAttributes.get()) {
                invalidation.addMainAttr(vec_entry);
            }
        }

        if (attributes.isActive()) {
            for (auto &vec_entry : attributes.get()) {
                invalidation.addAttr(vec_entry);
            }
        }

        if (objectType.isActive()) {
            auto type = object_names.find(objectType.get());
            if (type != object_names.end()) {
                invalidation.setObjectType(type->second);
            }
            else {
                dbgWarning(D_INTELLIGENCE) << "Received invalid object type: " << objectType.get();
            }
        }

        if (sourceId.isActive()) invalidation.setSourceId(sourceId.get());

        if (invalidationType.isActive()) {
            auto type = invalidation_type_names.find(invalidationType.get());
            if (type != invalidation_type_names.end()) {
                invalidation.setInvalidationType(type->second);
            }
            else {
                dbgWarning(D_INTELLIGENCE) << "Received invalid invalidation type: " << invalidationType.get();
            }
        }

        string registration_id = "";
        if (invalidationRegistrationId.isActive()) registration_id = invalidationRegistrationId.get();

        auto i_cb = Singleton::Consume<I_InvalidationCallBack>::from<InvalidationCallBack>();
        i_cb->performCallBacks(invalidation, registration_id);
    }

private:

    C2S_LABEL_PARAM(string, class_name, "class");
    C2S_OPTIONAL_PARAM(string, category);
    C2S_OPTIONAL_PARAM(string, family);
    C2S_OPTIONAL_PARAM(string, group);
    C2S_OPTIONAL_PARAM(string, order);
    C2S_OPTIONAL_PARAM(string, kind);
    C2S_OPTIONAL_PARAM(string, objectType);
    C2S_OPTIONAL_PARAM(string, sourceId);
    C2S_OPTIONAL_PARAM(string, invalidationRegistrationId);
    C2S_OPTIONAL_PARAM(vector<StrAttributes>, mainAttributes);
    C2S_OPTIONAL_PARAM(vector<StrAttributes>, attributes);
    C2S_OPTIONAL_PARAM(string, invalidationType);
};

class PagingController
{
public:
    PagingController()
    {
        uint request_overall_timeout_conf = getConfigurationWithDefault<uint>(
                20,
                "intelligence",
                "request overall timeout"
        );

        timer = Singleton::Consume<I_TimeGet>::by<IntelligenceComponentV2>();
        mainloop = Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();

        paging_timeout = timer->getMonotonicTime() + chrono::microseconds(request_overall_timeout_conf * 1000000);
    }

    bool
    isMoreResponses(const Maybe<Response> &res, const IntelligenceRequest &req)
    {
        response = res;
        if (!res.ok() || req.getPagingStatus().ok()) return false;
        if (res->getResponseStatus() != ResponseStatus::IN_PROGRESS) return false;
        dbgTrace(D_INTELLIGENCE) << "Intelligence paging response is in progress";
        mainloop->yield(true);
        return hasTimeoutRemaining();
    }

    Maybe<Response> getResponse() const { return response; }

private:
    bool
    hasTimeoutRemaining() const
    {
        if (timer->getMonotonicTime() < paging_timeout) return true;
        dbgDebug(D_INTELLIGENCE) << "Intelligence paging response reached timeout";
        return false;
    }

    chrono::microseconds paging_timeout;
    Maybe<Response> response = genError("Paging response is uninitialized");
    I_TimeGet *timer;
    I_MainLoop *mainloop;
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
        mainloop = Singleton::Consume<I_MainLoop>::by<IntelligenceComponentV2>();

        mainloop->addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::minutes(12),
            [this] () { sendRecurringInvalidationRegistration(); },
            "Sending intelligence invalidation"
        );

        auto rest_api = Singleton::Consume<I_RestApi>::by<IntelligenceComponentV2>();
        rest_api->addRestCall<ReceiveInvalidation>(RestAction::SET, "new-invalidation/source/invalidation");
    }

    bool
    sendInvalidation(const Invalidation &invalidation) const override
    {
        return sendIntelligence(invalidation).ok();
    }

    Maybe<uint>
    registerInvalidation(const Invalidation &invalidation, const function<void(const Invalidation &)> &cb) override
    {
        if (!invalidation.isLegalInvalidation()) return genError("Attempting to register invalid invalidation");
        auto res = invalidations.emplace(invalidation, cb);
        sendRecurringInvalidationRegistration();
        return res;
    }

    void
    unregisterInvalidation(uint id) override
    {
        invalidations.erase(id);
    }

    Maybe<Response>
    getResponse(
        const vector<QueryRequest> &query_requests,
        bool is_pretty,
        bool is_bulk,
        bool is_proxy,
        const MessageMetadata &req_md
    ) const override
    {
        IntelligenceRequest intelligence_req(query_requests, is_pretty, is_bulk, is_proxy, req_md);
        if (!intelligence_req.checkAssetsLimit().ok()) return intelligence_req.checkAssetsLimit().passErr();
        if (!intelligence_req.checkMinConfidence().ok()) return intelligence_req.checkMinConfidence().passErr();
        if (intelligence_req.isPagingActivated()) {
            auto is_paging_finished = intelligence_req.isPagingFinished();
            if (is_paging_finished.ok() && *is_paging_finished) {
                return genError("Paging is activated and already finished. No need for more queries.");
            }
        }
        auto response = sendIntelligenceRequest(intelligence_req);
        return response;
    }

    Maybe<Intelligence::Response>
    getResponse(
        const QueryRequest &query_request,
        bool is_pretty,
        bool is_proxy,
        const MessageMetadata &req_md
    ) const override
    {
        vector<QueryRequest> queries = {query_request};
        return getResponse(queries, is_pretty, false, is_proxy, req_md);
    }

private:
    bool
    hasLocalIntelligenceSupport() const
    {
        if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.useLocalIntelligence")) return true;

        auto crowsec_env = getenv("CROWDSEC_ENABLED");
        bool crowdsec_enabled = crowsec_env != nullptr && string(crowsec_env) == "true";

        if (getProfileAgentSettingWithDefault<bool>(crowdsec_enabled, "layer7AccessControl.crowdsec.enabled")) {
            return true;
        }

        if (getProfileAgentSettingWithDefault<bool>(false, "agent.config.supportInvalidation")) return true;
        dbgTrace(D_INTELLIGENCE) << "Local intelligence not supported";

        return false;
    }

    template <typename IntelligenceRest>
    Maybe<Response>
    sendIntelligence(const IntelligenceRest &rest_req) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending intelligence request";
        auto res = sendLocalIntelligenceToLocalServer(rest_req);
        if (res.ok()) return res;
        return sendGlobalIntelligence(rest_req);
    }

    template <typename IntelligenceRest>
    Maybe<Response>
    sendLocalIntelligenceToLocalServer(const IntelligenceRest &rest_req) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending local intelligence request";
        if (!hasLocalIntelligenceSupport()) {
            dbgDebug(D_INTELLIGENCE) << "Local intelligence not supported";
            return genError("Local intelligence not configured");
        }
        auto server = getSetting<string>("intelligence", "local intelligence server ip");
        if (!server.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Local intelligence server ip not configured";
            return genError("Local intelligence server ip not configured");
        }

        auto res = sendLocalIntelligenceToLocalServer(rest_req, *server, primary_port_setting);
        if (res.ok()) return res;
        return sendLocalIntelligenceToLocalServer(rest_req, *server, secondary_port_setting);
    }

    template <typename IntelligenceRest>
    Maybe<Response>
    sendLocalIntelligenceToLocalServer(
        const IntelligenceRest &rest_req,
        const string &server,
        const string &port_setting
    ) const
    {
        auto port = getSetting<uint>("intelligence", port_setting);
        if (!port.ok()) {
            dbgWarning(D_INTELLIGENCE) << "Could not resolve port for " + port_setting;
            return genError("Could not resolve port for " + port_setting);
        }

        dbgTrace(D_INTELLIGENCE)
            << "Intelligence rest request value: "
            << (rest_req.genJson().ok() ? rest_req.genJson().unpack() : rest_req.genJson().getErr());

        MessageMetadata req_md(server, *port);
        req_md.insertHeaders(getHTTPHeaders());
        req_md.setConnectioFlag(MessageConnectionConfig::UNSECURE_CONN);
        return sendIntelligenceRequestImpl(rest_req, req_md);
    }

    template <typename IntelligenceRest>
    Maybe<Response>
    sendGlobalIntelligence(const IntelligenceRest &rest_req) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending global intelligence request";

        dbgTrace(D_INTELLIGENCE)
            << "Intelligence rest value: "
            << (rest_req.genJson().ok() ? rest_req.genJson().unpack() : rest_req.genJson().getErr());
        MessageMetadata global_req_md;
        global_req_md.insertHeaders(getHTTPHeaders());
        return sendIntelligenceRequestImpl(rest_req, global_req_md);
    }

    Maybe<Response>
    createResponse(const string &response_body, const IntelligenceRequest &query_request) const
    {
        Response response(response_body, query_request.getSize(), query_request.isBulk());
        auto load_status = response.load();
        if (load_status.ok()) return response;
        dbgWarning(D_INTELLIGENCE) << "Could not create intelligence response.";
        return load_status.passErr();
    }

    Maybe<Response>
    sendIntelligenceRequestImpl(const Invalidation &invalidation, const MessageMetadata &local_req_md) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending intelligence invalidation";
        auto res = message->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            invalidation_uri,
            invalidation,
            MessageCategory::INTELLIGENCE,
            local_req_md
        );
        if (res) return Response();
        dbgWarning(D_INTELLIGENCE) << "Could not send local intelligence invalidation.";
        return genError("Could not send local intelligence invalidation");
    }

    Maybe<Response>
    sendIntelligenceRequestImpl(
        const InvalidationRegistration::RestCall &registration,
        const MessageMetadata &registration_req_md
    ) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending intelligence invalidation registration";
        auto res = message->sendSyncMessageWithoutResponse(
            HTTPMethod::POST,
            registration_uri,
            registration,
            MessageCategory::INTELLIGENCE,
            registration_req_md
        );
        if (res) return Response();
        dbgWarning(D_INTELLIGENCE) << "Could not send intelligence invalidation registration.";
        return genError("Could not send intelligence invalidation registration");
    }

    Maybe<Response>
    sendIntelligenceRequestImpl(const IntelligenceRequest &query_request, const MessageMetadata &global_req_md) const
    {
        dbgFlow(D_INTELLIGENCE) << "Sending intelligence query";
        auto json_body = query_request.genJson();
        if (!json_body.ok()) return json_body.passErr();
        auto req_data = message->sendSyncMessage(
                HTTPMethod::POST,
                query_request.isBulk() ? queries_uri : query_uri,
                *json_body,
                MessageCategory::INTELLIGENCE,
                global_req_md
        );
        if (!req_data.ok()) {
            auto response_error = req_data.getErr().toString();
            dbgWarning(D_INTELLIGENCE)
                << "Could not send intelligence query. "
                << req_data.getErr().getBody()
                << " "
                << req_data.getErr().toString();
            return genError("Could not send intelligence query.");
        } else if (req_data->getHTTPStatusCode() != HTTPStatusCode::HTTP_OK) {
            dbgWarning(D_INTELLIGENCE) << "Invalid intelligence response: " << req_data->toString();
            return genError(req_data->toString());
        }

        return createResponse(req_data->getBody(), query_request);
    }

    map<string, string>
    getHTTPHeaders() const
    {
        map<string, string> headers;
        auto details = Singleton::Consume<I_AgentDetails>::by<IntelligenceComponentV2>();
        auto tenant = details->getTenantId();
        if (tenant == "") tenant = "Global";
        headers["X-Tenant-Id"] = tenant;
        auto rest = Singleton::Consume<I_RestApi>::by<IntelligenceComponentV2>();
        auto agent = details->getAgentId() + ":" + to_string(rest->getListeningPort());
        headers["X-Source-Id"] = agent;

        return headers;
    }

    void
    sendRecurringInvalidationRegistration() const
    {
        if (invalidations.empty()) return;

        sendLocalIntelligenceToLocalServer(invalidations.getRegistration());
    }

    Maybe<Response>
    sendIntelligenceRequest(const IntelligenceRequest& req) const
    {
        PagingController paging;

        while (paging.isMoreResponses(sendIntelligence(req), req));

        return paging.getResponse();
    }

    InvalidationCallBack         invalidations;
    I_Messaging               *message = nullptr;
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
    registerExpectedConfiguration<bool>("intelligence", "support Invalidation");
    registerExpectedSetting<string>("intelligence", "local intelligence server ip");
    registerExpectedSetting<uint>("intelligence", primary_port_setting);
    registerExpectedSetting<uint>("intelligence", secondary_port_setting);

    registerExpectedConfigFile("agent-intelligence", Config::ConfigFileType::Policy);
}
