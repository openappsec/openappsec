#ifndef __RATE_LIMIT_H_
#define __RATE_LIMIT_H_

#include <string>

#include "component.h"
#include "singleton.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "i_generic_rulebase.h"

class RateLimit
    :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_GenericRulebase>
{
public:
    RateLimit();
    ~RateLimit();

    void preload() override;

    void init() override;
    void fini() override;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __RATE_LIMIT_H_
