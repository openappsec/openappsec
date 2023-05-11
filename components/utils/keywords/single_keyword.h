#ifndef ___SINGLE_KEYWORD_H__
#define ___SINGLE_KEYWORD_H__

#include <map>
#include <string>
#include <vector>
#include <memory>

#include "buffer.h"
#include "keyword_comp.h"
#include "debug.h"

USE_DEBUG_FLAG(D_KEYWORD);

enum class MatchStatus { Match, NoMatch, NoMatchFinal };

class KeywordError
{
public:
    KeywordError(const std::string &str) : err(str)
    {
    }

    const std::string &
    getErr() const
    {
        return err;
    }

private:
    std::string err;
};

class KeywordAttr
{
public:
    KeywordAttr(const std::string &str);

    const std::string&
    getAttrName() const
    {
        return params[0];
    }

    const std::vector<std::string> &
    getParams() const
    {
        return params;
    }

private:
    std::vector<std::string> params;
};

class KeywordParsed
{
public:
    KeywordParsed(const std::string &keyword);

    const std::string &
    getName() const
    {
        return name;
    }

    const std::vector<KeywordAttr> &
    getAttr() const
    {
        return attr;
    }

private:
    std::string name;
    std::vector<KeywordAttr> attr;
};

class I_KeywordRuntimeState
{
public:
    virtual uint getOffset(const std::string &ctx) const = 0;
    virtual uint getVariable(uint requested_var_id) const = 0;
protected:
    virtual ~I_KeywordRuntimeState()
    {
    }
};

class OffsetRuntimeState : public I_KeywordRuntimeState
{
public:
    OffsetRuntimeState(const I_KeywordRuntimeState *prev, const std::string &ctx, uint offset);
    virtual ~OffsetRuntimeState()
    {
    }
    uint getOffset(const std::string &requested_ctx_id) const override;
    uint getVariable(uint requested_var_id) const override;

private:
    const I_KeywordRuntimeState *prev;
    std::string ctx;
    uint offset;
};

class VariableRuntimeState : public I_KeywordRuntimeState
{
public:
    VariableRuntimeState(const I_KeywordRuntimeState *prev, uint var_id, uint val);
    virtual ~VariableRuntimeState()
    {
    }

    uint getOffset(const std::string &requested_ctx_id) const override;
    uint getVariable(uint requested_var_id) const override;

private:
    const I_KeywordRuntimeState *prev;
    uint var_id;
    uint value;
};

class VariablesMapping
{
public:
    uint addNewVariable(const std::string &name);
    Maybe<uint> getVariableId(const std::string &name) const;

private:
    std::map<std::string, uint> mapping;
};

class NumericAttr
{
    enum class Status { Unset, Const, Var };
public:
    void setAttr(
        const KeywordAttr &attr,
        const VariablesMapping &known_vars,
        const std::string &keyword_name,
        const uint base = 10,
        bool is_unsigned_val = false);

    void setAttr(
        const std::string &attr_name,
        const std::string &param,
        const VariablesMapping &known_vars,
        const std::string &keyword_name,
        const uint base = 10,
        bool is_unsigned_val = false);

    int evalAttr(const I_KeywordRuntimeState *prev) const;

    bool
    isConstant() const
    {
        return status!=Status::Var;
    }

    bool
    isSet() const
    {
        return status!=Status::Unset;
    }

private:
    Status status = Status::Unset;
    int val = 0;
};

class BoolAttr
{
public:
    void setAttr(const KeywordAttr &attr, const std::string &keyword_name);
    void setAttr(const std::string &keyword_name, const std::string &attr_name);

    operator bool() const
    {
        return val;
    }

private:
    bool val = false;
};

class CtxAttr
{
public:
    void setAttr(const KeywordAttr &attr, const std::string &keyword_name);

    operator std::string() const
    {
        if (!is_set) {
            auto env = Singleton::Consume<I_Environment>::by<KeywordComp>();
            auto default_ctx = env->get<std::string>(I_KeywordsRule::getKeywordsRuleTag());
            if (default_ctx.ok()) return *default_ctx;
            dbgError(D_KEYWORD) << "Running keyword rule without specific context and without default";
            return "Missing Default Context";
        }
        return ctx;
    }

private:
    std::string ctx;
    bool is_set = false;
};

class ComparisonAttr
{
public:
    enum class CompId
    {
        EQUAL,
        NOT_EQUAL,
        LESS_THAN,
        GREATER_THAN,
        LESS_THAN_OR_EQUAL,
        GREATER_THAN_OR_EQUAL
    };

    void setAttr(const std::string &param, const std::string &keyword_name);
    bool operator()(int first_val, int second_val) const;

    bool
    isSet() const
    {
        return is_set;
    }

private:
    Maybe<CompId> getComparisonByName(const std::string &name);

    const static std::map<std::string, CompId> name_to_operator;
    bool is_set = false;
    CompId comp_val;
};

class SingleKeyword
{
public:
    SingleKeyword()
    {
    }

    virtual ~SingleKeyword()
    {
    }

    MatchStatus runNext(const I_KeywordRuntimeState *curr) const;
    void appendKeyword(std::unique_ptr<SingleKeyword> &&_next);
    virtual MatchStatus isMatch(const I_KeywordRuntimeState *prev) const = 0;

private:
    std::unique_ptr<SingleKeyword> next;
};

std::unique_ptr<SingleKeyword> genDataKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genPCREKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genLengthKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genByteExtractKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genCompareKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genStateopKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genNoMatchKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> genJumpKeyword(
    const std::vector<KeywordAttr> &attr,
    VariablesMapping &vars
);

std::unique_ptr<SingleKeyword> getKeywordByName(
    const KeywordParsed &parsed_data,
    VariablesMapping &vars
);

#endif // ___SINGLE_KEYWORD_H__
