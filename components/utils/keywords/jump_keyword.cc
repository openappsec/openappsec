#include "single_keyword.h"
#include "output.h"
#include "debug.h"

#include <map>
#include <strings.h>

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class jumpKeyword : public SingleKeyword
{
public:
    explicit jumpKeyword(const vector<KeywordAttr> &attr, const VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState* prev) const override;

private:
    enum class JumpFromId
    {
        RELATIVE,
        FROM_BEGINNING,
        FROM_END
    };

    void
    setContext(const KeywordAttr &attr)
    {
        ctx.setAttr(attr, "byte_extract");
    }

    void
    setAlign(const KeywordAttr &attr)
    {
        if (align != 1) throw KeywordError("Double definition of the 'align' in the 'jump' keyword");
        auto &vec = attr.getParams();
        if (vec.size() != 2) throw KeywordError("Malformed 'align' in the 'jump' keyword");

        if (vec[1] == "2") {
            align = 2;
        } else if (vec[1] == "4") {
            align = 4;
        } else {
            throw KeywordError("Unknown 'align' in the 'jump' keyword: " + vec[1]);
        }
    }
    
    bool
    isConstant() const
    {
        return jumping_from != JumpFromId::RELATIVE && jumping_val.isConstant();
    }

    JumpFromId  jumping_from;
    NumericAttr jumping_val;
    int         align = 1;
    CtxAttr     ctx;

    static const map<string, void(jumpKeyword::*)(const KeywordAttr &)> setops;
    uint getStartOffset(uint buf_size, const I_KeywordRuntimeState *prev) const;
    uint applyAlignment(uint value) const;
    uint addOffset(uint offset, int add) const;
};

const map<string, void(jumpKeyword::*)(const KeywordAttr &)> jumpKeyword::setops = {
    { "part",            &jumpKeyword::setContext   },
    { "align",           &jumpKeyword::setAlign     }
};

jumpKeyword::jumpKeyword(const vector<KeywordAttr> &attrs, const VariablesMapping &vars)
{

    //two requied attributes - jumping value and jumping from
    if (attrs.size() < 2) throw KeywordError("Invalid number of attributes in the 'jump' keyword");

    //parisng first attribute (Required) - jumping value
    auto &jumping_val_param = attrs[0].getParams();
    if (jumping_val_param.size() != 1) {
        throw KeywordError("More than one element in the jumping value in the 'jump' keyword");
    }
    jumping_val.setAttr("jumping value", jumping_val_param[0], vars, "jump");

    //parisng second attribute (Required) - jumping from
    auto &jumping_from_param = attrs[1].getParams();
    if (jumping_from_param.size() != 1) {
        throw KeywordError("More than one element in the jumping 'from' parameter in the 'jump' keyword");
    }
    
    if (jumping_from_param[0] == "from_beginning") {
        jumping_from = JumpFromId::FROM_BEGINNING;
    } else if (jumping_from_param[0] == "from_end") {
        jumping_from = JumpFromId::FROM_END;
    } else if (jumping_from_param[0] == "relative") {
        jumping_from = JumpFromId::RELATIVE;
    } else {
        throw KeywordError("Unknown jumping 'from' parameter in the 'jump' keyword: " + jumping_from_param[0]);
    }

    //parisng optional attributes
    for (uint i = 2; i < attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute " + attrs[i].getAttrName() + " in the 'jump' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i]);
    }
}

uint
jumpKeyword::applyAlignment(uint value) const
{
    int reminder = value % align;
    if (reminder != 0) {
        value += (align - reminder);
    }
    return value;
}

uint
jumpKeyword::addOffset(uint offset, int add) const
{
    if (add < 0 && offset < static_cast<uint>(-add)) {
        dbgWarning(D_KEYWORD)
            << "The offset was set to 0 "
            << "due to an attempt to jump before the beginning of the buffer in the 'jump' keyword";
        return 0;
    }
    return applyAlignment(offset + add);
}

uint
jumpKeyword::getStartOffset(uint buf_size, const I_KeywordRuntimeState *prev) const
{
    switch (jumping_from) {
        case JumpFromId::FROM_BEGINNING: {
            return 0;
        }
        case JumpFromId::FROM_END: {
            return buf_size;
        }
        case JumpFromId::RELATIVE: {
            return prev->getOffset(ctx);
        }
    }
    dbgAssert(false) << "Invalid jumping 'from' parameter";
    return 0;
}

MatchStatus
jumpKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    auto part = Singleton::Consume<I_Environment>::by<KeywordComp>()->get<Buffer>(static_cast<string>(ctx));

    if (!part.ok()) return MatchStatus::NoMatchFinal;

    uint start_offset = getStartOffset((*part).size(), prev);

    uint offset_to_jump = addOffset(start_offset, jumping_val.evalAttr(prev));

    if (offset_to_jump > (*part).size()) {
        dbgDebug(D_KEYWORD) << "New offset exceeds the buffer size in the 'jump' keyword";
        return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
    }

    OffsetRuntimeState new_offset(prev, ctx, offset_to_jump);
    return runNext(&new_offset);
}

unique_ptr<SingleKeyword>
genJumpKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<jumpKeyword>(attr, known_vars);
}
