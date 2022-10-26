#include "tostring.h"

#include "cptest.h"

using namespace std;
using namespace testing;

TEST(ToStringTest, basic)
{
    ToString str;
    EXPECT_EQ("", static_cast<string>(str));

    string tmp = str;
    EXPECT_EQ("", tmp);
}

TEST(ToStringTest, one_parameter)
{
    ToString str("aaa");
    EXPECT_EQ(string("aaa"), static_cast<string>(str));
}

TEST(ToStringTest, three_parameters)
{
    ToString str("R", 8, 0);
    EXPECT_EQ(string("R80"), static_cast<string>(str));
}

TEST(ToStringTest, operator)
{
    ToString str;
    str << 'R' << 80;
    EXPECT_EQ(string("R80"), static_cast<string>(str));
}

TEST(ToStringTest, reset)
{
    ToString str("aaa");
    EXPECT_EQ(string("aaa"), static_cast<string>(str));
    str.reset();
    EXPECT_EQ(string(), static_cast<string>(str));
}
