#include "single_keyword.h"
#include "output.h"
#include "debug.h"

#include <map>
#include <strings.h>
#include "limits.h"

using namespace std;

USE_DEBUG_FLAG(D_KEYWORD);

class ByteExtractKeyword : public SingleKeyword
{
public:
    explicit ByteExtractKeyword(const vector<KeywordAttr> &attr, VariablesMapping &vars);
    MatchStatus isMatch(const I_KeywordRuntimeState *prev) const override;

private:
    enum class BaseId
    {
        BIN,
        HEX = 16,
        DEC = 10,
        OCT = 8
    };

    void
    setOffset(const KeywordAttr &attr, const VariablesMapping &vars)
    {
        offset.setAttr(attr, vars, "byte_extract");
    }

    void
    setRelative(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_relative.setAttr(attr, "byte_extract");
    }

    void
    setLittleEndian(const KeywordAttr &attr, const VariablesMapping &)
    {
        is_little_end.setAttr(attr, "byte_extract");
    }

    void
    setDataType(const KeywordAttr &attr, const VariablesMapping &)
    {
        if (data_type != BaseId::BIN) {
            throw KeywordError("Double definition of the data type in the 'byte_extract' keyword");
        }

        auto &vec = attr.getParams();
        if (vec.size() != 2) throw KeywordError("Malformed data type in the 'byte_extract' keyword");

        if (vec[1] == "hex") {
            data_type = BaseId::HEX;
        } else if (vec[1] == "dec") {
            data_type = BaseId::DEC;
        } else if (vec[1] == "oct") {
            data_type = BaseId::OCT;
        } else {
            throw KeywordError("Unknown data type in the 'byte_extract' keyword: " + vec[1]);
        }
    }

    void
    setContext(const KeywordAttr &attr, const VariablesMapping &)
    {
        ctx.setAttr(attr, "byte_extract");
    }

    void
    setAlign(const KeywordAttr &attr, const VariablesMapping &)
    {
        if (align != 1) throw KeywordError("Double definition of the 'align' in the 'byte_extract' keyword");
        auto &vec = attr.getParams();
        if (vec.size() != 2) throw KeywordError("Malformed 'align' in the 'byte_extract' keyword");

        if (vec[1] == "2") {
            align = 2;
        } else if (vec[1] == "4") {
            align = 4;
        } else {
            throw KeywordError("Unknown 'align' in the 'byte_extract' keyword: " + vec[1]);
        }
    }

    bool
    isConstant() const
    {
        return !is_relative && bytes.isConstant() && offset.isConstant();
    }

    pair<uint, uint> getStartOffsetAndLength(uint buf_size, const I_KeywordRuntimeState *prev) const;
    uint applyAlignment(uint value) const;
    Maybe<uint> readValue(uint start, uint length, const Buffer &buf) const;
    Maybe<uint> readStringValue(uint start, uint length, const Buffer &buf) const;

    NumericAttr bytes;
    uint        var_id;
    NumericAttr offset;
    BoolAttr    is_relative;
    BoolAttr    is_little_end;
    BaseId      data_type = BaseId::BIN;
    int         align = 1;
    CtxAttr     ctx;

    static const map<string, void(ByteExtractKeyword::*)(const KeywordAttr &, const VariablesMapping &)> setops;
};

const map<string, void(ByteExtractKeyword::*)(const KeywordAttr &, const VariablesMapping &)>
ByteExtractKeyword::setops = {
    { "offset",             &ByteExtractKeyword::setOffset       },
    { "relative",           &ByteExtractKeyword::setRelative     },
    { "little_endian",      &ByteExtractKeyword::setLittleEndian },
    { "string",             &ByteExtractKeyword::setDataType     },
    { "part",               &ByteExtractKeyword::setContext      },
    { "align",              &ByteExtractKeyword::setAlign        }
};

ByteExtractKeyword::ByteExtractKeyword(const vector<KeywordAttr> &attrs, VariablesMapping &vars)
        :
    offset()
{
    //two requied attributes - number of bytes and var name
    if (attrs.size() < 2) throw KeywordError("Invalid number of attributes in the 'byte_extract' keyword");

    //parisng first attribute (Required) - number of bytes
    auto &bytes_param = attrs[0].getParams();
    if (bytes_param.size() != 1) {
        throw KeywordError("More than one element in the 'bytes' in the 'byte_extract' keyword");
    }
    bytes.setAttr("bytes", bytes_param[0], vars, "byte_extract", static_cast<uint>(BaseId::DEC), true);
    if (bytes.isConstant() && bytes.evalAttr(nullptr) == 0) {
        throw KeywordError("Number of bytes is zero in the 'byte_extract' keyword");
    }

    //parisng second attribute (Required) - variable name
    auto &var_name_param = attrs[1].getParams();
    if (var_name_param.size() != 1) {
        throw KeywordError("More than one element in the variable name in the 'byte_extract' keyword");
    }
    const string &var_name = var_name_param[0];
    auto curr = setops.find(var_name);
    if (curr != setops.end()) {
        throw KeywordError("'" + var_name + "' cannot be the variable name in the 'byte_extract' keyword");
    }
    if (isdigit(var_name[0]) || var_name[0] == '-') {
        throw KeywordError("Malformed variable name in the 'byte_extract' keyword");
    }

    var_id = vars.addNewVariable(var_name);

    //parsing the other optional attributes
    for (uint i = 2; i < attrs.size(); i++) {
        auto curr = setops.find(attrs[i].getAttrName());
        if (curr == setops.end()) {
            throw KeywordError("Unknown attribute '" + attrs[i].getAttrName() + "' in the 'byte_extract' keyword");
        }
        auto set_func = curr->second;
        (this->*set_func)(attrs[i], vars);
    }

    if (data_type == BaseId::BIN) {
        if (!bytes.isConstant()) {
            throw KeywordError("Data type is binary, but the 'bytes' is not constant in the 'byte_extract' keyword");
        }
        int num_bytes = bytes.evalAttr(nullptr);
        if (num_bytes != 1 && num_bytes != 2 && num_bytes != 4) {
            throw KeywordError("Data type is binary, but the 'bytes' is not constant in the 'byte_extract' keyword");
        }
        if (is_little_end && num_bytes == 1) {
            throw KeywordError(
                "Little endian is set, "
                "but the number of bytes is invalid in the 'byte_extract' keyword"
            );
        }
        if (align != 1) {
            throw KeywordError("The 'align' is set and data type is binary in the 'byte_extract' keyword");
        }
    } else {
        if (is_little_end) {
            throw KeywordError("Little endian is set, but the data type is not binary in the 'byte_extract' keyword");
        }
    }
}

static uint
addOffset(uint offset, int add)
{
    if (add < 0 && offset < static_cast<uint>(-add)) {
        dbgWarning(D_KEYWORD)
            << "The offset was set to 0 "
            << "due to an attempt to jump before the beginning of the buffer in the 'jump' keyword";
        return 0;
    }
    return offset + add;
}

pair<uint, uint>
ByteExtractKeyword::getStartOffsetAndLength(uint buf_size, const I_KeywordRuntimeState *prev) const
{
    uint relative_offset = is_relative ? prev->getOffset(ctx) : 0;
    int offset_attr = offset.evalAttr(prev);
    uint start_offset = addOffset(relative_offset, offset_attr);

    if (start_offset >= buf_size) return make_pair(0, 0);

    uint length = buf_size - start_offset;
    return make_pair(start_offset, length);
}

Maybe<uint>
ByteExtractKeyword::readValue(uint start, uint length, const Buffer &buf) const
{
    if (data_type != BaseId::BIN) return readStringValue(start, length, buf);

    uint res = 0;
    for (uint i = 0; i < length; i++) {
        uint ch = buf[start + i];
        if (is_little_end) {
            ch <<= 8*i;
            res += ch;
        } else {
            res <<= 8;
            res += ch;
        }
    }
    return res;
}

Maybe<uint>
ByteExtractKeyword::readStringValue(uint start, uint length, const Buffer &buf) const
{
    const u_char *data = buf.getPtr(start, length).unpack(); // start and length were checked outside of the function
    string val_str(reinterpret_cast<const char *>(data), length);

    uint base = static_cast<uint>(data_type);
    try {
        size_t idx;
        auto res = stoul(val_str, &idx, base);
        if (idx != val_str.length()) throw invalid_argument("");
        if (res > INT_MAX) {
            throw out_of_range("");
        }
        return res;
    }
    catch (invalid_argument &) {
        return genError("Unable to convert the \"" + val_str + "\" to a number due to an invalid argument");
    }
    catch (out_of_range &) {
        return genError(
            "Unable to convert the \""
            + val_str
            + "\" to a number. The maximum is: "
            + to_string(INT_MAX)
        );
    }
}

uint
ByteExtractKeyword::applyAlignment(uint value) const
{
    int reminder = value % align;
    if (reminder != 0) {
        value += (align - reminder);
    }
    return value;
}

MatchStatus
ByteExtractKeyword::isMatch(const I_KeywordRuntimeState *prev) const
{
    auto part = Singleton::Consume<I_Environment>::by<KeywordComp>()->get<Buffer>(static_cast<string>(ctx));

    if (!part.ok()) return MatchStatus::NoMatchFinal;

    uint bytes_to_extr = bytes.evalAttr(prev);
    if (bytes_to_extr == 0) {
        dbgDebug(D_KEYWORD) << "Number of bytes is zero in the 'byte_extract' keyword";
        return MatchStatus::NoMatch;  //the case of constant number of bytes was checked during compilation
    }
    
    uint start_offset, length_to_end;
    tie(start_offset, length_to_end) = getStartOffsetAndLength((*part).size(), prev);

    uint offset_after_extracted_bytes = applyAlignment(start_offset + bytes_to_extr);

    if (length_to_end == 0 || offset_after_extracted_bytes > (*part).size()) {
        dbgDebug(D_KEYWORD)
            << "Offset after the number of bytes to extract exceeds the buffer size in the 'byte_extract' keyword";
        return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
    }

    auto res = readValue(start_offset, bytes_to_extr, *part);
    if (!res.ok()) {
        dbgDebug(D_KEYWORD) << "Trying to store an invalid value in the 'byte_extract' keyword: " + res.getErr();
        return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
    }

    uint extracted_val = res.unpack();

    if (extracted_val > INT_MAX) {
        dbgDebug(D_KEYWORD) << "Value exceeds the maximum in the 'byte_extract' keyword";
        return isConstant() ? MatchStatus::NoMatchFinal : MatchStatus::NoMatch;
    }

    //add variable and move offset after number of extracted bytes
    VariableRuntimeState new_var(prev, var_id, extracted_val);
    OffsetRuntimeState new_offset(&new_var, ctx, offset_after_extracted_bytes);
    return runNext(&new_offset);
}

unique_ptr<SingleKeyword>
genByteExtractKeyword(const vector<KeywordAttr> &attr, VariablesMapping &known_vars)
{
    return make_unique<ByteExtractKeyword>(attr, known_vars);
}
