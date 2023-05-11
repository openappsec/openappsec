#include "ips_configuration.h"
#include "debug.h"

using namespace std;

IPSConfiguration::Context::Context(ContextType _type, uint history) : type(_type), history_size(history) {}

uint
IPSConfiguration::Context::getHistorySize() const
{
    dbgAssert(type == ContextType::HISTORY) << "Try to access history size for non-history context";
    return history_size;
}

static const map<string, IPSConfiguration::ContextType> type_convertor = {
    { "normal",  IPSConfiguration::ContextType::NORMAL },
    { "keep",    IPSConfiguration::ContextType::KEEP },
    { "history", IPSConfiguration::ContextType::HISTORY }
};

class ContextConfigurationJSON
{
public:
    void
    load(cereal::JSONInputArchive &ar)
    {
        string type_name;
        ar(
            cereal::make_nvp("name", name),
            cereal::make_nvp("type", type_name)
        );

        auto type_pointer = type_convertor.find(type_name);
        if (type_pointer == type_convertor.end()) reportConfigurationError("Unknown IPS context type: " + type_name);
        type = type_pointer->second;

        if (type == IPSConfiguration::ContextType::HISTORY) ar(cereal::make_nvp("historySize", size));
    }

    string getName() const { return name; }
    IPSConfiguration::Context getContext() const { return IPSConfiguration::Context(type, size); }

private:
    string name;
    IPSConfiguration::ContextType type;
    uint size = 0;
};

void
IPSConfiguration::load(cereal::JSONInputArchive &ar)
{
    vector<ContextConfigurationJSON> config;
    ar(cereal::make_nvp("contextsConfiguration", config));

    for (auto &context : config) {
        context_config.emplace(context.getName(), context.getContext());
    }
}

IPSConfiguration::Context
IPSConfiguration::getContext(const string &name) const
{
    auto context = context_config.find(name);
    if (context == context_config.end()) return IPSConfiguration::Context();
    return context->second;
}

uint
IPSConfiguration::getHistorySize(const string &name) const
{
    auto context = context_config.find(name);
    dbgAssert(context != context_config.end()) << "Try to access history size for non-exiting context";
    return context->second.getHistorySize();
}
