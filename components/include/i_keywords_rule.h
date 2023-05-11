#ifndef ___I_KEYWORDS_RULE_H__
#define ___I_KEYWORDS_RULE_H__

#include <memory>
#include <string>

#include "maybe_res.h"

class I_KeywordsRule
{
public:
    class VirtualRule
    {
    public:
        virtual ~VirtualRule() {};
        virtual bool isMatch() const = 0;
    };

    virtual Maybe<std::shared_ptr<VirtualRule>> genRule(const std::string &rule) = 0;

    static const std::string & getKeywordsRuleTag() { return keywords_tag; }

protected:
    virtual ~I_KeywordsRule() {}

private:
    static std::string keywords_tag;
};

#endif // ___I_KEYWORDS_RULE_H__
