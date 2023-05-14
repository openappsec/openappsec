#include "ips_comp.h"

#include <algorithm>

#include "debug.h"
#include "new_table_entry.h"
#include "ips_entry.h"
#include "ips_configuration.h"
#include "ips_signatures.h"
#include "ips_metric.h"
#include "generic_rulebase/parameters_config.h"
#include "config.h"
#include "virtual_modifiers.h"
#include "helper.h"
#include "ips_common_types.h"
#include "nginx_attachment_common.h"

using namespace std;

USE_DEBUG_FLAG(D_IPS);

static const Buffer header_sep(": ", 2, Buffer::MemoryType::STATIC);
static const Buffer line_sep("\r\n", 2, Buffer::MemoryType::STATIC);
static const Buffer space(" ", 1, Buffer::MemoryType::STATIC);
static const Buffer x_forworded_for_key("x-forworded-for", 15, Buffer::MemoryType::STATIC);
static const Buffer log_sep(", ", 2, Buffer::MemoryType::STATIC);
static const Buffer empty_buffer("", 0, Buffer::MemoryType::STATIC);

static const string cookie("cookie");
static const string oauth("_oauth2_proxy");
static const string jsessionid("jsessionid");
static const string xff("x-forwarded-for");
static const string header("header");
static const string source_ip("source ip");

class IPSComp::Impl
        :
    public Singleton::Provide<I_FirstTierAgg>::SelfInterface,
    public Listener<NewTableEntry>,
    public Listener<NewHttpTransactionEvent>,
    public Listener<HttpRequestHeaderEvent>,
    public Listener<HttpRequestBodyEvent>,
    public Listener<EndRequestEvent>,
    public Listener<ResponseCodeEvent>,
    public Listener<HttpResponseHeaderEvent>,
    public Listener<HttpResponseBodyEvent>,
    public Listener<EndTransactionEvent>
{
    static constexpr auto DROP = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_DROP;
    static constexpr auto ACCEPT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_ACCEPT;
    static constexpr auto INSPECT = ngx_http_cp_verdict_e::TRAFFIC_VERDICT_INSPECT;

    class SigsFirstTierAgg
    {
    public:
        const shared_ptr<PMHook> &
        getHook(const set<PMPattern> &new_pat)
        {
            auto old_size = pats.size();
            pats.insert(new_pat.begin(), new_pat.end());

            if (pats.size() != old_size) {
                if (!hook->prepare(pats).ok()) {
                    reportConfigurationError("failed to compile first tier");
                }
            }

            return hook;
        }

    private:
        set<PMPattern> pats;
        shared_ptr<PMHook> hook = make_shared<PMHook>();
    };

public:
    void
    preload()
    {
        function<void()> cb = [&](){ clearAggCache(); };
        registerConfigPrepareCb(cb);
        registerConfigLoadCb(cb);
        registerConfigAbortCb(cb);
    }

    void
    init()
    {
        ips_metric.init(
            "IPS Stats",
            ReportIS::AudienceTeam::AGENT_CORE,
            ReportIS::IssuingEngine::AGENT_CORE,
            std::chrono::minutes(10),
            true,
            ReportIS::Audience::SECURITY
        );
        ips_metric.registerListener();
        registerListener();
        table = Singleton::Consume<I_Table>::by<IPSComp>();
        env = Singleton::Consume<I_Environment>::by<IPSComp>();
    }

    void
    fini()
    {
        unregisterListener();
    }

    void
    upon(const NewTableEntry &) override
    {
        if (isSignatureListsEmpty()) return;
        auto table = Singleton::Consume<I_Table>::by<IPSComp>();
        table->createState<IPSEntry>();
        table->getState<IPSEntry>().uponEnteringContext();
    }

    string getListenerName() const override { return "ips application"; }

    EventVerdict
    respond(const NewHttpTransactionEvent &event) override
    {
        if (isSignatureListsEmpty()) return ACCEPT;
        table->createState<IPSEntry>();
        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        Buffer method(event.getHttpMethod());
        ips_state.addPendingContext("HTTP_METHOD", method);

        Buffer uri(event.getURI());
        ips_state.addPendingContext("HTTP_COMPLETE_URL_ENCODED", uri);

        auto decoder = makeVirtualContainer<HexDecoder<'%'>>(event.getURI());
        vector<u_char> decoded_url(decoder.begin(), decoder.end());
        auto start = find(decoded_url.begin(), decoded_url.end(), static_cast<u_char>('?'));

        if (start != decoded_url.end()) {
            vector<u_char> query(start + 1, decoded_url.end());
            ips_state.addPendingContext("HTTP_QUERY_DECODED", Buffer(move(query)));
        }
        vector<u_char> path(decoded_url.begin(), start);
        ips_state.addPendingContext("HTTP_PATH_DECODED", Buffer(move(path)));
        ips_state.addPendingContext("HTTP_COMPLETE_URL_DECODED", Buffer(move(decoded_url)));

        Buffer protocol(event.getHttpProtocol());
        ips_state.addPendingContext("HTTP_PROTOCOL", protocol);

        auto full_line = method + space + uri + space + protocol + line_sep;
        ips_state.addPendingContext("HTTP_RAW", full_line);

        return INSPECT;
    }

    static string
    getHeaderContextName(const Buffer &name)
    {
        string name_str = name;
        transform(name_str.begin(), name_str.end(), name_str.begin(), ::toupper);
        return "HTTP_REQUEST_HEADER_" + name_str;
    }

    EventVerdict
    respond(const HttpRequestHeaderEvent &event) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        auto header_value = event.getKey() + header_sep + event.getValue();
        ips_state.addPendingContext("HTTP_REQUEST_ONE_HEADER", header_value);
        auto full_header = header_value + line_sep;
        ips_state.addPendingContext("HTTP_REQUEST_HEADER", full_header);
        ips_state.addPendingContext(getHeaderContextName(event.getKey()), event.getValue());
        ips_state.addPendingContext("HTTP_RAW", full_header);

        auto max_size = getConfigurationWithDefault<uint>(1536, "IPS", "Max Field Size");

        // Add request header for log
        auto maybe_req_headers_for_log = ips_state.getTransactionData(IPSCommonTypes::requests_header_for_log);
        if (!maybe_req_headers_for_log.ok()) {
            ips_state.setTransactionData(IPSCommonTypes::requests_header_for_log, header_value);
        } else if ((maybe_req_headers_for_log.unpack()).size() + log_sep.size() + header_value.size() < max_size) {
            Buffer request_headers_for_log = maybe_req_headers_for_log.unpack() + log_sep;
            request_headers_for_log += header_value;
            ips_state.setTransactionData(IPSCommonTypes::requests_header_for_log, request_headers_for_log);
        }

        addRequestHdr(event.getKey(), event.getValue());
        if (event.isLastHeader()) {
            for (auto &context : ips_state.getPendingContexts()) {
                if (isDropContext(context.first, context.second)) setDrop(ips_state);
            }
            ips_state.clearPendingContexts();
            if (isDrop(ips_state)) return DROP;
        }

        return INSPECT;
    }

    EventVerdict
    respond(const HttpRequestBodyEvent &event) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        if (isDropContext("HTTP_REQUEST_BODY", event.getData())) setDrop(ips_state);

        if (!ips_state.isFlagSet("HttpRequestData")) {
            ips_state.setFlag("HttpRequestData");
            auto data =
                ips_state.getBuffer("HTTP_METHOD") +
                space +
                ips_state.getBuffer("HTTP_COMPLETE_URL_DECODED") +
                space +
                ips_state.getBuffer("HTTP_PROTOCOL") +
                line_sep +
                ips_state.getBuffer("HTTP_REQUEST_HEADER") +
                line_sep +
                event.getData();
            if (isDropContext("HTTP_REQUEST_DATA", data)) setDrop(ips_state);
        }

        if (isDropContext("HTTP_RAW", event.getData())) setDrop(ips_state);

        return INSPECT;
    }

    EventVerdict
    respond(const EndRequestEvent &) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        if (!ips_state.isFlagSet("HttpRequestData")) {
            ips_state.setFlag("HttpRequestData");
            auto data =
                ips_state.getBuffer("HTTP_METHOD") +
                space +
                ips_state.getBuffer("HTTP_COMPLETE_URL_DECODED") +
                space +
                ips_state.getBuffer("HTTP_PROTOCOL") +
                line_sep +
                ips_state.getBuffer("HTTP_REQUEST_HEADER") +
                line_sep;
            if (isDropContext("HTTP_REQUEST_DATA", data)) return DROP;
        }

        if (isDrop(ips_state)) return DROP;

        if (isContextActive("HTTP_RESPONSE_HEADER")) return INSPECT;
        if (isContextActive("HTTP_RESPONSE_BODY")) return INSPECT;
        return ACCEPT;
    }

    EventVerdict
    respond(const ResponseCodeEvent &event) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        Buffer buf(reinterpret_cast<const char *>(&event), sizeof(event), Buffer::MemoryType::VOLATILE);
        if (isDropContext("HTTP_RESPONSE_CODE", buf)) return DROP;

        return INSPECT;
    }

    EventVerdict
    respond(const HttpResponseHeaderEvent &event) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        if (isDropContext("HTTP_RESPONSE_HEADER", event.getValue())) return DROP;

        return INSPECT;
    }

    EventVerdict
    respond(const HttpResponseBodyEvent &event) override
    {
        if (!table->hasState<IPSEntry>()) return ACCEPT;

        auto &ips_state = table->getState<IPSEntry>();
        ips_state.uponEnteringContext();
        auto leave_context = make_scope_exit([&ips_state] () { ips_state.uponLeavingContext(); });

        if (isDropContext("HTTP_RESPONSE_BODY", event.getData())) return DROP;

        return event.isLastChunk() ? ACCEPT : INSPECT;
    }

    EventVerdict respond (const EndTransactionEvent &) override { return ACCEPT; }

private:
    static void setDrop(IPSEntry &state) { state.setDrop(); }
    static bool isDrop(const IPSEntry &state) { return state.isDrop(); }

    bool
    isDropContext(const string &name, const Buffer &buf)
    {
        auto responeses = ParsedContext(buf, name, 0).query();
        for (auto &reponse : responeses) {
            if (reponse == ParsedContextReply::DROP) return true;
        }
        return false;
    }

    static bool
    isContextActive(const string &context)
    {
        return !getConfigurationWithDefault(IPSSignatures(), "IPS", "IpsProtections").isEmpty(context) ||
            !getConfigurationWithDefault(SnortSignatures(), "IPSSnortSigs", "SnortProtections").isEmpty(context);
    }

    static bool
    isSignatureListsEmpty()
    {
        return getConfigurationWithDefault(IPSSignatures(), "IPS", "IpsProtections").isEmpty() &&
            getConfigurationWithDefault(SnortSignatures(), "IPSSnortSigs", "SnortProtections").isEmpty();
    }

    void
    addRequestHdr(const Buffer &name, const Buffer &value)
    {
        auto &ips_state = table->getState<IPSEntry>();
        ips_state.setTransactionData(name, value);
    }

    shared_ptr<PMHook>
    getHook(const string &context_name, const set<PMPattern> &patterns) override
    {
        return tier_aggs[context_name].getHook(patterns);
    }

    void clearAggCache() { tier_aggs.clear(); }

    I_Table *table = nullptr;
    I_Environment *env = nullptr;
    IPSSignatureSubTypes::IPSMetric ips_metric;
    map<string, SigsFirstTierAgg> tier_aggs;
};

IPSComp::IPSComp() : Component("IPSComp"), pimpl(make_unique<Impl>()) {}

IPSComp::~IPSComp() {}

void
IPSComp::preload()
{
    registerExpectedResource<IPSSignaturesResource>("IPS", "protections");
    registerExpectedResource<string>("IPS", "VersionId");
    registerExpectedResource<SnortSignaturesResource>("IPSSnortSigs", "protections");
    registerExpectedConfiguration<IPSConfiguration>("IPS", "IpsConfigurations");
    registerExpectedConfiguration<uint>("IPS", "Max Field Size");
    registerExpectedConfiguration<IPSSignatures>("IPS", "IpsProtections");
    registerExpectedConfiguration<SnortSignatures>("IPSSnortSigs", "SnortProtections");
    registerExpectedConfigFile("ips", Config::ConfigFileType::Policy);
    registerExpectedConfigFile("ips", Config::ConfigFileType::Data);
    registerExpectedConfigFile("snort", Config::ConfigFileType::Policy);

    ParameterException::preload();

    pimpl->preload();
}

void
IPSComp::init()
{
    pimpl->init();
}

void
IPSComp::fini()
{
    pimpl->fini();
}
