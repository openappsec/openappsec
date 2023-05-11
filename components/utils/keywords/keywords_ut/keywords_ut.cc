#include "keyword_comp.h"
#include "environment.h"
#include "mock/mock_table.h"
#include "cptest.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "config.h"
#include "config_component.h"

using namespace std;

class KeywordsRuleTest : public ::testing::Test
{
public:
    void
    appendBuffer(const string &id, const string &str)
    {
        buffers[id] += Buffer(str);
    }

    string
    ruleCompileFail(const string &_rule)
    {
        auto rule = Singleton::Consume<I_KeywordsRule>::from(comp)->genRule(_rule);
        EXPECT_FALSE(rule.ok()) << "Compile supposed to fail";
        return rule.getErr();
    }

    bool
    ruleRun(const string &_rule, const string &default_ctx = "default")
    {
        auto rule = Singleton::Consume<I_KeywordsRule>::from(comp)->genRule(_rule);
        EXPECT_TRUE(rule.ok()) << "Compile not supposed to fail: " << rule.getErr();
        ScopedContext ctx;
        ctx.registerValue(I_KeywordsRule::getKeywordsRuleTag(), default_ctx);
        for (auto &value : buffers) {
            ctx.registerValue(value.first, value.second);
        }
        return (*rule)->isMatch();
    }

private:
    KeywordComp comp;
    ::testing::NiceMock<MockMainLoop> mock_mainloop;
    ::testing::NiceMock<MockTimeGet> mock_timer;
    Environment env;
    map<string, Buffer> buffers;
};

TEST_F(KeywordsRuleTest, data_basic_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123456789");

    EXPECT_TRUE(ruleRun("data: \"234\" , part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("data: \"234\";", "HTTP_RESPONSE_BODY"));
    EXPECT_FALSE(ruleRun("data: \"75\", part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, data_relative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("data: \"567\", part HTTP_RESPONSE_BODY; data: \"234\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(
        ruleRun("data: \"567\", part HTTP_RESPONSE_BODY; data: \"234\", part HTTP_RESPONSE_BODY, relative;")
    );
    EXPECT_TRUE(ruleRun("data: \"234\", part HTTP_RESPONSE_BODY; data: \"567\", part HTTP_RESPONSE_BODY, relative;"));
}

TEST_F(KeywordsRuleTest, data_depth_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("data: \"345\", depth 5, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"345\", depth 4, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, data_nocase_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "abcdefg");

    EXPECT_TRUE(ruleRun("data: \"cde\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"CDE\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("data: \"CDE\", nocase, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, data_offset_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("data: \"345\", offset 2, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"345\", offset 3, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, data_caret_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY, caret;"));
    EXPECT_TRUE(ruleRun("data: \"345\", caret, part HTTP_RESPONSE_BODY, offset 2;"));
}

TEST_F(KeywordsRuleTest, data_negative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_FALSE(ruleRun("data: !\"345\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("data: !\"365\", part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, data_part_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");
    appendBuffer("HTTP_REQUEST_BODY", "abcdefg");

    EXPECT_TRUE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY; data: \"cde\", part HTTP_REQUEST_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"345\", part HTTP_RESPONSE_BODY; data: \"cde\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("data: \"345\", part HTTP_REQUEST_BODY; data: \"cde\", part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, pcre_basic_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("pcre: \"/5.7/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/5..7/\", part HTTP_RESPONSE_BODY;"));
}


TEST_F(KeywordsRuleTest, pcre_relative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("pcre: \"/5.7/\", part HTTP_RESPONSE_BODY; pcre: \"/2.4/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/5.7/\", part HTTP_RESPONSE_BODY; pcre: \"/2.4/R\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(
        ruleRun("pcre: \"/5.7/\", part HTTP_RESPONSE_BODY; pcre: \"/2.4/\", relative, part HTTP_RESPONSE_BODY;")
    );
    EXPECT_TRUE(ruleRun("pcre: \"/2.4/\", part HTTP_RESPONSE_BODY; pcre: \"/5.7/R\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(
        ruleRun("pcre: \"/2.4/\", part HTTP_RESPONSE_BODY; pcre: \"/5.7/\", relative, part HTTP_RESPONSE_BODY;")
    );
}

TEST_F(KeywordsRuleTest, pcre_depth_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("pcre: \"/3.5/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("pcre: \"/3.5/\", depth 5, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/3.5/\", depth 4, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, pcre_nocase_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "abcdefg");

    EXPECT_TRUE(ruleRun("pcre: \"/c.e/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/C.E/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("pcre: \"/C.E/i\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("pcre: \"/C.E/\", nocase, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, pcre_offset_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("pcre: \"/3.5/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("pcre: \"/3.5/\", offset 2, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/3.5/\", offset 300, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, pcre_part_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");
    appendBuffer("HTTP_REQUEST_BODY", "abcdefg");

    EXPECT_TRUE(ruleRun("pcre: \"/3.5/\", part HTTP_RESPONSE_BODY; pcre: \"/c.e/\", part HTTP_REQUEST_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/3.5/\", part HTTP_RESPONSE_BODY; pcre: \"/c.e/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("pcre: \"/3.5/\", part HTTP_REQUEST_BODY; pcre: \"/c.e/\", part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, pcre_negative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_FALSE(ruleRun("pcre: !\"/3.5/\", part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("pcre: !\"/3..5/\", part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, compare_comparison_test) {
    EXPECT_TRUE(ruleRun("compare: 0, =, 0;"));
    EXPECT_TRUE(ruleRun("compare: -1, =, -1;"));
    EXPECT_FALSE(ruleRun("compare: 0, =, 1;"));
    EXPECT_FALSE(ruleRun("compare: -1, =, -2;"));
    EXPECT_FALSE(ruleRun("compare: 1, =, -1;"));
    EXPECT_FALSE(ruleRun("compare: -1, =, 1;"));
    EXPECT_TRUE(ruleRun("compare: 2, !=, 3;"));
    EXPECT_TRUE(ruleRun("compare: 2, <=, 3;"));
    EXPECT_TRUE(ruleRun("compare: 2, <, 3;"));
    EXPECT_FALSE(ruleRun("compare: 2, >, 3;"));
    EXPECT_FALSE(ruleRun("compare: 2, >=, 3;"));
    EXPECT_TRUE(ruleRun("compare: -2, !=, -3;"));
    EXPECT_TRUE(ruleRun("compare: -2, >=, -3;"));
    EXPECT_TRUE(ruleRun("compare: -2, >, -3;"));
    EXPECT_FALSE(ruleRun("compare: -2, <, -3;"));
    EXPECT_FALSE(ruleRun("compare: -2, <=, -3;"));
    EXPECT_TRUE(ruleRun("compare: -2, !=, 3;"));
    EXPECT_TRUE(ruleRun("compare: -2, <=, 3;"));
    EXPECT_TRUE(ruleRun("compare: -2, <, 3;"));
    EXPECT_FALSE(ruleRun("compare: -2, >, 3;"));
    EXPECT_FALSE(ruleRun("compare: -2, >=, 3;"));
    EXPECT_TRUE(ruleRun("compare: 2, !=, -3;"));
    EXPECT_TRUE(ruleRun("compare: 2, >=, -3;"));
    EXPECT_TRUE(ruleRun("compare: 2, >, -3;"));
    EXPECT_FALSE(ruleRun("compare: 2, <, -3;"));
    EXPECT_FALSE(ruleRun("compare: 2, <=, -3;"));
}

TEST_F(KeywordsRuleTest, compare_compile_fail_test) {
    EXPECT_EQ(ruleCompileFail("compare: 0;"), "Invalid number of attributes in the 'compare' keyword");
    EXPECT_EQ(ruleCompileFail("compare: 0, =;"), "Invalid number of attributes in the 'compare' keyword");
    EXPECT_EQ(ruleCompileFail("compare: 0, =, 0, 0;"), "Invalid number of attributes in the 'compare' keyword");
    EXPECT_EQ(
        ruleCompileFail("compare: 0 1, =, 0;"),
        "More than one element in the first value in the 'compare' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("compare: 0, = =, 0;"),
        "More than one element in the comparison operator in the 'compare' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("compare: 0, =, 0 1;"),
        "More than one element in the second value in the 'compare' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("compare: 0, ==, 0;"),
        "Unknown comparison operator in the 'compare' keyword: Could not find the operator: =="
    );
}

TEST_F(KeywordsRuleTest, length_basic_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123456789");
    appendBuffer("HTTP_REQUEST_BODY", "");

    EXPECT_TRUE(
        ruleRun(
            "length: length_var, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 9;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "length: length_var, part HTTP_REQUEST_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "length: length_var, part HTTP_REQUEST_BODY;"
            "compare: length_var, =, 1;"
        )
    );
}

TEST_F(KeywordsRuleTest, length_part_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("length: length_var, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("length: length_var, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, length_relative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123456789");

    EXPECT_TRUE(
        ruleRun(
            "data: \"234\", part HTTP_RESPONSE_BODY;"
            "length: relative_length_var, part HTTP_RESPONSE_BODY, relative;"
            "compare: relative_length_var, =, 5;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"234\", part HTTP_RESPONSE_BODY;"
            "length: relative_length_var, part HTTP_RESPONSE_BODY;"
            "compare: relative_length_var, =, 5;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "data: \"89\", part HTTP_RESPONSE_BODY;"
            "length: zero_length_var, part HTTP_RESPONSE_BODY, relative;"
            "compare: zero_length_var, =, 0;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"89\", part HTTP_RESPONSE_BODY;"
            "length: zero_length_var, part HTTP_RESPONSE_BODY;"
            "compare: zero_length_var, =, 0;"
        )
    );
}

TEST_F(KeywordsRuleTest, length_compare_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123");
    EXPECT_FALSE(ruleRun("length: 6, min, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("length: 6, exact, part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("length: 6, max, part HTTP_RESPONSE_BODY;"));

    appendBuffer("HTTP_RESPONSE_BODY", "456");
    EXPECT_TRUE(ruleRun("length: 6, min, part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("length: 6, exact, part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(ruleRun("length: 6, max, part HTTP_RESPONSE_BODY;"));

    appendBuffer("HTTP_RESPONSE_BODY", "789");
    EXPECT_TRUE(ruleRun("length: 6, min, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("length: 6, exact, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("length: 6, max, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, length_compile_fail_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123456789");

    EXPECT_EQ(
        ruleCompileFail("length: two_elem 2, part HTTP_RESPONSE_BODY;"),
        "More than one element in the variable name in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length: relative, part HTTP_RESPONSE_BODY;"),
        "The 'relative' cannot be the variable name in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length: part, part HTTP_RESPONSE_BODY;"),
        "The 'part' cannot be the variable name in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length: -minus, part HTTP_RESPONSE_BODY;"),
        "Malformed variable name in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length: 1digit, part HTTP_RESPONSE_BODY;"),
        "Malformed variable name in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length: bad_attr, partt HTTP_RESPONSE_BODY;"),
        "Unknown attribute 'partt' in the 'length' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("length:;"),
        "Invalid number of attributes in the 'length' keyword"
    );
}

TEST_F(KeywordsRuleTest, byte_extract_dec_string_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234");

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, dec_var, string dec, part HTTP_RESPONSE_BODY;"
            "data: \"234\", offset dec_var, part HTTP_RESPONSE_BODY;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 1, dec_var, string dec, part HTTP_RESPONSE_BODY;"
            "data: \"123\", offset dec_var, part HTTP_RESPONSE_BODY;"
        )
    );

    appendBuffer("HTTP_REQUEST_BODY", "A");

    EXPECT_FALSE(ruleRun("byte_extract: 1, bad_dec_var, string dec, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, byte_extract_hex_string_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "A123");

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, hex_var, string hex, part HTTP_RESPONSE_BODY;"
            "compare: hex_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 2, hex_var, string hex, part HTTP_RESPONSE_BODY;"
            "compare: hex_var, =, 161;"
        )
    );

    appendBuffer("HTTP_REQUEST_BODY", "10G");

    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 2, hex_var, string hex, part HTTP_REQUEST_BODY;"
            "compare: hex_var, =, 10;"
        )
    );
    EXPECT_FALSE(ruleRun("byte_extract: 3, bad_hex_var, string oct, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, byte_extract_oct_string_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "13ABC");

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 2, oct_var, string oct, part HTTP_RESPONSE_BODY;"
            "compare: oct_var, =, 11;"
        )
    );

    appendBuffer("HTTP_REQUEST_BODY", "118");

    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 2, oct_var, string oct, part HTTP_REQUEST_BODY;"
            "compare: oct_var, =, 13;"
        )
    );
    EXPECT_FALSE(ruleRun("byte_extract: 3, bad_oct_var, string oct, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, byte_extract_binary_data_test) {
    string one_byte_binary_data = {10};
    appendBuffer("HTTP_RESPONSE_BODY", one_byte_binary_data);

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, binary_data_var, part HTTP_RESPONSE_BODY;"
            "compare: binary_data_var, =, 10;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 1, dec_data_var, offset 2, string dec, part HTTP_RESPONSE_BODY;"
            "compare: dec_data_var, =, 10;"
        )
    );

    string two_bytes_binary_data = {1, 0, 0};
    appendBuffer("HTTP_REQUEST_BODY", two_bytes_binary_data);

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 2, binary_data_var, part HTTP_REQUEST_BODY;"
            "compare: binary_data_var , =, 256;"
        )
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 3, not1/2/4, part HTTP_REQUEST_BODY;"),
        "Data type is binary, but the 'bytes' is not constant in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail(
            "byte_extract: 1, no_constant, part HTTP_REQUEST_BODY;"
            "byte_extract: no_constant, var, part HTTP_REQUEST_BODY;"
        ),
        "Data type is binary, but the 'bytes' is not constant in the 'byte_extract' keyword"
    );
}

TEST_F(KeywordsRuleTest, byte_extract_bad_num_of_bytes_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "0");

    EXPECT_EQ(
        ruleCompileFail("byte_extract: 0, zero_bytes_var, string dec, part HTTP_RESPONSE_BODY;"),
        "Number of bytes is zero in the 'byte_extract' keyword"
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 1, one_byte_var, string dec, part HTTP_RESPONSE_BODY;"
            "byte_extract: one_byte_var, zero_bytes_var, string dec, part HTTP_RESPONSE_BODY;"
        )
    );
}

TEST_F(KeywordsRuleTest, byte_extract_part_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123");
    EXPECT_TRUE(ruleRun("byte_extract: 1, part_var, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("byte_extract: 1, part_var, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, byte_extract_offset_test) {
    appendBuffer("HTTP_REQUEST_BODY", "1A23456789hello");

    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 1, hex_var, offset 1, string hex, part HTTP_REQUEST_BODY; "
            "data: \"9hell\", offset hex_var, part HTTP_REQUEST_BODY;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, hex_var, offset 1, string hex, part HTTP_REQUEST_BODY;"
            "data: \"hell\", offset hex_var, part HTTP_REQUEST_BODY;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 1, dec_var, offset -1, string dec, part HTTP_REQUEST_BODY;"
            "data: \"1A2\", offset dec_var, part HTTP_REQUEST_BODY;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, dec_var, offset -1, string dec, part HTTP_REQUEST_BODY;"
            "data: \"A2\", offset dec_var, part HTTP_REQUEST_BODY;"
        )
    );
}

TEST_F(KeywordsRuleTest, byte_extract_relative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "123456789");

    EXPECT_TRUE(
        ruleRun(
            "data: \"12\", part HTTP_RESPONSE_BODY;"
            "byte_extract: 1, relative_var, relative, string dec, part HTTP_RESPONSE_BODY;"
            "compare: relative_var, =, 3;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"12\", part HTTP_RESPONSE_BODY;"
            "byte_extract: 1, non_relative_var, string dec, part HTTP_RESPONSE_BODY;"
            "compare: non_relative_var, =, 3;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"89\", part HTTP_RESPONSE_BODY;"
            "byte_extract: 1, relative_var, string dec, relative, part HTTP_RESPONSE_BODY;"
        )
    );
}

TEST_F(KeywordsRuleTest, byte_extract_endianness_test) {
    string little_end_test_str = {8, 0, 0};
    appendBuffer("HTTP_RESPONSE_BODY", little_end_test_str);

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 2, lit_end_var, little_endian, part HTTP_RESPONSE_BODY;"
            "compare: lit_end_var, =, 8;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 2, big_end_var, part HTTP_RESPONSE_BODY;"
            "compare: big_end_var, =, 8;"
        )
    );

    little_end_test_str[1] = 0;
    little_end_test_str[2] = 1;
    appendBuffer("HTTP_REQUEST_BODY", little_end_test_str);

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 2, lit_end_with_offset_var,"
            "offset 1, little_endian, part HTTP_REQUEST_BODY;"
            "compare: lit_end_with_offset_var, =, 256;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "byte_extract: 2, big_end_with_offset_var, offset 1, part HTTP_REQUEST_BODY;"
            "compare: big_end_with_offset_var, =, 256;"
        )
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, var, little_endian, part HTTP_REQUEST_BODY;"),
        "Little endian is set, but the number of bytes is invalid in the 'byte_extract' keyword"
    );

    EXPECT_EQ(
        ruleCompileFail("byte_extract: 2, no_binary, little_endian, string dec, part HTTP_REQUEST_BODY;"),
        "Little endian is set, but the data type is not binary in the 'byte_extract' keyword"
    );
}

TEST_F(KeywordsRuleTest, byte_extract_align_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234");

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, align2_var, align 2, string dec, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 2;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, align4_var, align 4, string dec, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, align2_var, offset 3, align 2, string dec, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, align4_var, offset 3, align 4, string dec, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );

    appendBuffer("HTTP_REQUEST_BODY", "123");

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: 1, align2_var, offset 1, align 2, string dec, part HTTP_REQUEST_BODY;"
            "length: length_var, relative, part HTTP_REQUEST_BODY;"
            "compare: length_var, =, 1;"
        )
    );
    EXPECT_FALSE(ruleRun("byte_extract: 1, align4_var, align 4, string dec, part HTTP_REQUEST_BODY;"));
    EXPECT_FALSE(ruleRun("byte_extract: 1, align2_var, offset 2, align 2, string dec, part HTTP_REQUEST_BODY;"));

    string binary_data_str = { 1 };
    appendBuffer("HTTP_REQUEST_BODY", binary_data_str);

    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, align_binary_var, align 2, part HTTP_REQUEST_BODY;"),
        "The 'align' is set and data type is binary in the 'byte_extract' keyword"
    );
}

TEST_F(KeywordsRuleTest, byte_extract_overflow_test) {
    string overflow_dec_data_str = to_string((uint)INT_MAX + 1);
    appendBuffer("HTTP_RESPONSE_BODY", overflow_dec_data_str);

    EXPECT_FALSE(
        ruleRun(
            "byte_extract: " + to_string(overflow_dec_data_str.length()) + ","
            "overflow_var, string dec, part HTTP_RESPONSE_BODY;"
        )
    );

    string max_value_dec_data_str = to_string(INT_MAX);
    appendBuffer("HTTP_REQUEST_BODY", max_value_dec_data_str);

    EXPECT_TRUE(
        ruleRun(
            "byte_extract: " + to_string(max_value_dec_data_str.length()) + ","
            "max_var, string dec, part HTTP_REQUEST_BODY;"
            "compare: max_var, =, " + max_value_dec_data_str + ";"
        )
    );

    string overflow_binary_data_str = { 0x7f, 0x7f, 0x7f, 0x7f, 0 };
    appendBuffer("HTTP_REQUEST_HEADERS", overflow_binary_data_str);

    EXPECT_FALSE(ruleRun("byte_extract: 5 ,overflow_num_var, string dec, part HTTP_REQUEST_HEADERS;"));
}

TEST_F(KeywordsRuleTest, byte_extract_compile_fail_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1 2, dec_var, string dec, part HTTP_RESPONSE_BODY;"),
        "More than one element in the 'bytes' in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, dec_var 1, string dec, part HTTP_RESPONSE_BODY;"),
        "More than one element in the variable name in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, align, string dec, part HTTP_RESPONSE_BODY;"),
        "'align' cannot be the variable name in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, -1, string dec, part HTTP_RESPONSE_BODY;"),
        "Malformed variable name in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_data_type, string dechex, part HTTP_RESPONSE_BODY;"),
        "Unknown data type in the 'byte_extract' keyword: dechex"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, 1var, string dec, part HTTP_RESPONSE_BODY;"),
        "Malformed variable name in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_align, align 3, part HTTP_RESPONSE_BODY;"),
        "Unknown 'align' in the 'byte_extract' keyword: 3"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_constant, offset 0x;"),
        "Malformed constant '0x' in the 'offset' in the 'byte_extract' keyword"
    );
    EXPECT_EQ(ruleCompileFail("byte_extract: 1;"), "Invalid number of attributes in the 'byte_extract' keyword");
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_attr, offset;"),
        "Malformed offset' in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_attr, string hex dec;"),
        "Malformed data type in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_attr, ofset 5;"),
        "Unknown attribute 'ofset' in the 'byte_extract' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("byte_extract: 1, bad_align, align 2 4;"),
        "Malformed 'align' in the 'byte_extract' keyword"
    );
}

TEST_F(KeywordsRuleTest, jump_from_beginning_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 9;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 9;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: -1, from_beginning, part HTTP_RESPONSE_BODY;"
            "length: length_var, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 10, from_beginning, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_FALSE(ruleRun("jump: 11, from_beginning, part HTTP_RESPONSE_BODY;"));
}

TEST_F(KeywordsRuleTest, jump_relative_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(
        ruleRun(
            "data: \"1\", part HTTP_RESPONSE_BODY;"
            "jump: 1, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 8;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"1\", part HTTP_RESPONSE_BODY;"
            "jump: 1, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 9;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "data: \"1\", part HTTP_RESPONSE_BODY;"
            "jump: -2, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "data: \"1\", part HTTP_RESPONSE_BODY;"
            "jump: 9, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "data: \"1\", part HTTP_RESPONSE_BODY;"
            "jump: 10, relative, part HTTP_RESPONSE_BODY;"
        )
    );
}

TEST_F(KeywordsRuleTest, jump_from_end_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_FALSE(ruleRun("jump: 1, from_end, part HTTP_RESPONSE_BODY;"));
    EXPECT_TRUE(
        ruleRun(
            "jump: -1, from_end, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 1;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: -10, from_end, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: -11, from_end, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
}

TEST_F(KeywordsRuleTest, combined_jumps_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: -1, from_end, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 1;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: -1, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: -1, from_end, part HTTP_RESPONSE_BODY;"
            "jump: 1, relative, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 0;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: -1, from_end, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 1;"
        )
    );
}


TEST_F(KeywordsRuleTest, jump_alignment_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, align 2, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 8;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 1, from_beginning, align 4, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 6;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 3, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: 2, relative, align 2, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 4;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "jump: 3, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: 2, relative, align 2, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 7;"
        )
    );
    EXPECT_FALSE(
        ruleRun(
            "jump: 3, from_beginning, part HTTP_RESPONSE_BODY;"
            "jump: 2, relative, align 4, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 3;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 2, from_beginning, align 2, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 8;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 4, from_beginning, align 4, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 6;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 0, from_beginning, align 2, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
    EXPECT_TRUE(
        ruleRun(
            "jump: 0, from_beginning, align 4, part HTTP_RESPONSE_BODY;"
            "length: length_var, relative, part HTTP_RESPONSE_BODY;"
            "compare: length_var, =, 10;"
        )
    );
}

TEST_F(KeywordsRuleTest, jump_part_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_TRUE(ruleRun("jump: 1, from_beginning, part HTTP_RESPONSE_BODY;"));
    EXPECT_FALSE(ruleRun("jump: 1, from_beginning, part HTTP_REQUEST_BODY;"));
}

TEST_F(KeywordsRuleTest, jump_compile_fail_test) {
    appendBuffer("HTTP_RESPONSE_BODY", "1234567890");

    EXPECT_EQ(ruleCompileFail("jump: 1;"), "Invalid number of attributes in the 'jump' keyword");
    EXPECT_EQ(
        ruleCompileFail("jump: 2 1, from_beginning;"),
        "More than one element in the jumping value in the 'jump' keyword"
    );
    EXPECT_EQ(
        ruleCompileFail("jump: 2, from_relative;"),
        "Unknown jumping 'from' parameter in the 'jump' keyword: from_relative"
    );
    EXPECT_EQ(ruleCompileFail("jump: 2, relative, align 3;"), "Unknown 'align' in the 'jump' keyword: 3");
    EXPECT_EQ(ruleCompileFail("jump: 2, relative, align 1;"), "Unknown 'align' in the 'jump' keyword: 1");
    EXPECT_EQ(ruleCompileFail("jump: 2, relative, align2 2;"), "Unknown attribute align2 in the 'jump' keyword");
    EXPECT_EQ(ruleCompileFail("jump: 2, relative, align 2 4;"), "Malformed 'align' in the 'jump' keyword");
    EXPECT_EQ(
        ruleCompileFail("jump: 2, from_beginning relative;"),
        "More than one element in the jumping 'from' parameter in the 'jump' keyword"
    );
}

TEST_F(KeywordsRuleTest, stateop)
{
    using testing::_;

    ConfigComponent conf;
    testing::StrictMock<MockTable> table;

    std::unique_ptr<TableOpaqueBase> opq;
    TableOpaqueBase *opq_ptr;
    bool has_stage = false;
    EXPECT_CALL(table, createStateRValueRemoved(_, _))
        .WillOnce(testing::DoAll(
            testing::Invoke(
                [&] (const type_index &, std::unique_ptr<TableOpaqueBase> &other)
                {
                    opq = std::move(other);
                    opq_ptr = opq.get();
                    has_stage = true;
                }
            ),
            testing::Return(true)
        ));
    EXPECT_CALL(table, getState(_)).WillRepeatedly(testing::ReturnPointee(&opq_ptr));
    EXPECT_CALL(table, hasState(_)).WillRepeatedly(testing::ReturnPointee(&has_stage));

    EXPECT_FALSE(ruleRun("stateop: state sss, isset;"));

    EXPECT_TRUE(ruleRun("stateop: state sss, unset;"));
    EXPECT_FALSE(ruleRun("stateop: state sss, isset;"));

    EXPECT_TRUE(ruleRun("stateop: state sss, set;"));
    EXPECT_TRUE(ruleRun("stateop: state sss, isset;"));
    EXPECT_FALSE(ruleRun("stateop: state dd, isset;"));

    EXPECT_TRUE(ruleRun("stateop: state sss, unset;"));
    EXPECT_FALSE(ruleRun("stateop: state sss, isset;"));
}

TEST_F(KeywordsRuleTest, no_match)
{
    EXPECT_FALSE(ruleRun("no_match;"));
}
