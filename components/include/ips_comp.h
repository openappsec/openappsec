#ifndef __IPS_COMP_H__
#define __IPS_COMP_H__

#include "singleton.h"
#include "i_keywords_rule.h"
#include "i_table.h"
#include "i_http_manager.h"
#include "i_environment.h"
#include "http_inspection_events.h"
#include "i_generic_rulebase.h"
#include "component.h"

class IPSComp
        :
    public Component,
    Singleton::Consume<I_KeywordsRule>,
    Singleton::Consume<I_Table>,
    Singleton::Consume<I_Environment>,
    Singleton::Consume<I_GenericRulebase>
{
public:
    IPSComp();
    ~IPSComp();

    void preload();

    void init();
    void fini();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __IPS_COMP_H__
