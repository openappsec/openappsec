#ifndef __KEYWORD_COMP__
#define __KEYWORD_COMP__

#include <memory>

#include "singleton.h"
#include "i_environment.h"
#include "i_table.h"
#include "i_keywords_rule.h"
#include "component.h"

class KeywordComp
        :
    public Component,
    Singleton::Provide<I_KeywordsRule>,
    Singleton::Consume<I_Table>,
    Singleton::Consume<I_Environment>
{
public:
    KeywordComp();
    ~KeywordComp();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __KEYWORD_COMP__
