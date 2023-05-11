#ifndef __IPS_CONFIGURATION_H__
#define __IPS_CONFIGURATION_H__

#include "config.h"

class IPSConfiguration
{
public:
    enum class ContextType { NORMAL, KEEP, HISTORY };

    class Context {
    public:
        Context() : type(ContextType::NORMAL), history_size(0) {}
        Context(ContextType type, uint history);

        ContextType getType() const { return type; }
        uint getHistorySize() const;

    private:
        ContextType type;
        uint history_size;
    };

    IPSConfiguration() {}
    IPSConfiguration(const std::map<std::string, Context> &initial_conf) : context_config(initial_conf) {}

    void load(cereal::JSONInputArchive &ar);

    Context getContext(const std::string &name) const;
    uint getHistorySize(const std::string &name) const;

private:
    std::map<std::string, Context> context_config;
};

#endif // __IPS_CONFIGURATION_H__
