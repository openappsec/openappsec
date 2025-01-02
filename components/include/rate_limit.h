#ifndef __RATE_LIMIT_H_
#define __RATE_LIMIT_H_

#include <string>

#include "component.h"
#include "singleton.h"
#include "i_mainloop.h"
#include "i_environment.h"
#include "i_geo_location.h"
#include "i_generic_rulebase.h"
#include "i_shell_cmd.h"
#include "i_env_details.h"

class RateLimit
    :
    public Component,
    Singleton::Consume<I_MainLoop>,
    Singleton::Consume<I_TimeGet>,
    Singleton::Consume<I_GeoLocation>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_GenericRulebase>,
    Singleton::Consume<I_ShellCmd>,
    Singleton::Consume<I_EnvDetails>
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
