#include "ips_entry.h"
#include "ips_signatures.h"
#include "ips_configuration.h"
#include "config.h"
#include "debug.h"
#include "common.h"
#include "i_keywords_rule.h"
#include "helper.h"

using namespace std;
using namespace IPSHelper;

USE_DEBUG_FLAG(D_IPS);

static const map<string, IPSConfiguration::Context> default_conf_mapping = {
    { "HTTP_METHOD",               IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_COMPLETE_URL_DECODED", IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_PATH_DECODED",         IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_QUERY_DECODED",        IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_PROTOCOL",             IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_REQUEST_HEADER",       IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_REQUEST_BODY",         IPSConfiguration::Context(IPSConfiguration::ContextType::HISTORY, 1000) },
    { "HTTP_RESPONSE_CODE",        IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_RESPONSE_HEADER",      IPSConfiguration::Context(IPSConfiguration::ContextType::KEEP, 0) },
    { "HTTP_RESPONSE_BODY",        IPSConfiguration::Context(IPSConfiguration::ContextType::HISTORY, 1000) }
};

static const IPSConfiguration default_conf(default_conf_mapping);

IPSEntry::IPSEntry() : TableOpaqueSerialize<IPSEntry>(this) {}

void
IPSEntry::upon(const ParsedContext &)
{
}

ParsedContextReply
IPSEntry::respond(const ParsedContext &parsed)
{
    const auto &name = parsed.getName();
    auto buf = parsed.getBuffer();

    dbgDebug(D_IPS) << "Entrying context " << name;
    dbgTrace(D_IPS) << "Context Content " << dumpHex(buf);

    auto config = getConfigurationWithDefault(default_conf, "IPS", "IpsConfigurations").getContext(name);
    if (config.getType() == IPSConfiguration::ContextType::HISTORY) {
        buf = past_contexts[name] + buf;
    }
    ctx.registerValue(I_KeywordsRule::getKeywordsRuleTag(), name);
    ctx.registerValue(name, buf);

    ctx.activate();
    auto &signatures = getConfigurationWithDefault(IPSSignatures(), "IPS", "IpsProtections");
    bool should_drop = signatures.isMatchedPrevent(parsed.getName(), buf);
    auto &snort_signatures = getConfigurationWithDefault(SnortSignatures(), "IPSSnortSigs", "SnortProtections");
    should_drop |= snort_signatures.isMatchedPrevent(parsed.getName(), buf);
    ctx.deactivate();

    switch(config.getType()) {
        case IPSConfiguration::ContextType::NORMAL: {
            ctx.unregisterKey<Buffer>(name);
            break;
        }
        case IPSConfiguration::ContextType::KEEP: {
            past_contexts[name] += buf;
            ctx.registerValue(name, past_contexts[name]);
            break;
        }
        case IPSConfiguration::ContextType::HISTORY: {
            if (buf.size() > config.getHistorySize()) buf.keepTail(config.getHistorySize());
            ctx.registerValue(name, buf);
            past_contexts[name] = buf;
            break;
        }
    }

    dbgDebug(D_IPS) << "Return " << (should_drop ? "drop" : "continue");

    return should_drop ? ParsedContextReply::DROP : ParsedContextReply::ACCEPT;
}

Buffer
IPSEntry::getBuffer(const string &name) const
{
    auto elem = past_contexts.find(name);
    if (elem != past_contexts.end()) return elem->second;

    for (auto &p : pending_contexts) {
        if (p.first == name) return p.second;
    }

    return Buffer();
}

void
IPSEntry::setTransactionData(const Buffer &key, const Buffer &value)
{
    transaction_data[key] = value;
}

Maybe<Buffer>
IPSEntry::getTransactionData(const Buffer &key) const
{
    map<Buffer, Buffer>::const_iterator iter = transaction_data.find(key);
    
    if (iter == transaction_data.end()) {
        return genError("Http header value not found");
    }

    return iter->second;

}

string
IPSEntry::name()
{
    return "IPS";
}

unique_ptr<TableOpaqueBase>
IPSEntry::prototype()
{
    return make_unique<IPSEntry>();
}

uint
IPSEntry::currVer()
{
    return 0;
}

uint
IPSEntry::minVer()
{
    return 0;
}

void
IPSEntry::addPendingContext(const std::string &name, const Buffer &buffer)
{
    pending_contexts.emplace_back(name, buffer);
}
