#ifndef __I_FIRST_TIER_AGG_H__
#define __I_FIRST_TIER_AGG_H__

#include <memory>
#include <set>
#include <string>

#include "pm_hook.h"

class I_FirstTierAgg
{
public:
    virtual std::shared_ptr<PMHook> getHook(const std::string &context_name, const std::set<PMPattern> &patterns) = 0;

protected:
    virtual ~I_FirstTierAgg() {}
};

#endif // __I_FIRST_TIER_AGG_H__
