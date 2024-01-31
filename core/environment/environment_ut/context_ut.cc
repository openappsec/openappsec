#include "cptest.h"
#include "context.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

class ContextTest : public Test
{
public:
    Context ctx;

    class TestObject
    {
    public:
        TestObject(const string &_x, int _y) : x(_x), y(_y) {};

        bool
        operator==(const TestObject &rsh) const
        {
            return x == rsh.x && y == rsh.y;
        }

    private:
        string x;
        int    y;
    };

    static Maybe<int, Context::Error> maybeIntFunc() { return 1; }
    static Maybe<double, Context::Error> maybeDoubleFunc() { return 1.1; }
    static Maybe<string, Context::Error> maybeStrFunc() { return string("str1"); }
    static Maybe<char, Context::Error> maybeCharFunc() { return 'a'; }
    static Maybe<TestObject, Context::Error> maybeObjectFunc() { return ContextTest::TestObject("test_object", 1); }
    static int intFunc() { return 2; }
    static double doubleFunc() { return 2.2; }
    static string strFunc() { return string("str2"); }
    static char charFunc() { return 'b'; }
    static TestObject objectFunc() { return ContextTest::TestObject("test_object", 2); }
};

std::ostream &
operator<<(std::ostream &os, const Context::Error &)
{
    return os;
}

std::ostream &
operator<<(std::ostream &os, const ContextTest::TestObject &)
{
    return os;
}

TEST_F(ContextTest, register_int)
{
    ctx.registerValue("_int", 10);
    EXPECT_THAT(ctx.get<int>("_int"), IsValue(10));
}

TEST_F(ContextTest, register_double)
{
    ctx.registerValue("_double", 2.2);
    EXPECT_THAT(ctx.get<double>("_double"), IsValue(2.2));
}

TEST_F(ContextTest, register_char)
{
    ctx.registerValue("_char", 'a');
    EXPECT_THAT(ctx.get<char>("_char"), IsValue('a'));
}

TEST_F(ContextTest, register_string)
{
    ctx.registerValue("_string", string("string"));
    EXPECT_THAT(ctx.get<string>("_string"), IsValue("string"));
}

TEST_F(ContextTest, register_object)
{
    ctx.registerValue("_obj", ContextTest::TestObject("value", 1));
    EXPECT_THAT(ctx.get<TestObject>("_obj"), IsValue(ContextTest::TestObject("value", 1)));
}

TEST_F(ContextTest, register_2_values_same_key)
{
    ctx.registerValue("same_value_key", 1);
    ctx.registerValue("same_value_key", 2);
    EXPECT_THAT(ctx.get<int>("same_value_key"), IsValue(2));
}

TEST_F(ContextTest, register_2_values_same_key_diff_context)
{
    ConfigComponent conf;
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ::Environment env;
    auto i_env = Singleton::Consume<I_Environment>::from(env);
    ctx.registerValue("same_value_key", 1);
    ctx.activate();
    EXPECT_THAT(i_env->get<int>("same_value_key"), IsValue(1));
    Context another_ctx;
    another_ctx.registerValue("same_value_key", 2);
    another_ctx.activate();
    EXPECT_THAT(i_env->get<int>("same_value_key"), IsValue(2));
}

TEST_F(ContextTest, register_2_func_same_key)
{
    ctx.registerFunc<int>("same_func_key", ContextTest::maybeIntFunc);
    ctx.registerFunc<double>("same_func_key", ContextTest::maybeDoubleFunc);
    EXPECT_THAT(ctx.get<double>("same_func_key"), IsValue(1.1));
}

TEST_F(ContextTest, register_return_maybe_obj_func)
{
    ctx.registerFunc<TestObject>("maybe_obj_func", ContextTest::maybeObjectFunc);
    EXPECT_THAT(ctx.get<TestObject>("maybe_obj_func"), IsValue(ContextTest::TestObject("test_object", 1)));
}

TEST_F(ContextTest, register_return_maybe_int_func)
{
    ctx.registerFunc<int>("maybe_int_func", ContextTest::maybeIntFunc);
    EXPECT_THAT(ctx.get<int>("maybe_int_func"), IsValue(1));
}

TEST_F(ContextTest, register_return_maybe_str_func)
{
    ctx.registerFunc<string>("maybe_str_func", ContextTest::maybeStrFunc);
    EXPECT_THAT(ctx.get<string>("maybe_str_func"), IsValue("str1"));
}

TEST_F(ContextTest, register_return_maybe_double_func)
{
    ctx.registerFunc<double>("maybe_double_func", ContextTest::maybeDoubleFunc);
    EXPECT_THAT(ctx.get<double>("maybe_double_func"), IsValue(1.1));
}

TEST_F(ContextTest, register_return_maybe_char_func)
{
    ctx.registerFunc<char>("maybe_char_func", ContextTest::maybeCharFunc);
    EXPECT_THAT(ctx.get<char>("maybe_char_func"), IsValue('a'));
}

TEST_F(ContextTest, register_return_obj_func)
{
    ctx.registerFunc<TestObject>("obj_func", ContextTest::objectFunc);
    EXPECT_THAT(ctx.get<TestObject>("obj_func"), IsValue(ContextTest::TestObject("test_object", 2)));
}

TEST_F(ContextTest, register_return_int_func)
{
    ctx.registerFunc<int>("int_func", ContextTest::intFunc);
    EXPECT_THAT(ctx.get<int>("int_func"), IsValue(2));
}

TEST_F(ContextTest, register_return_str_func)
{
    ctx.registerFunc<string>("str_func", ContextTest::strFunc);
    EXPECT_THAT(ctx.get<string>("str_func"), IsValue("str2"));
}

TEST_F(ContextTest, register_return_double_func)
{
    ctx.registerFunc<double>("double_func", ContextTest::doubleFunc);
    EXPECT_THAT(ctx.get<double>("double_func"), IsValue(2.2));
}

TEST_F(ContextTest, register_return_char_func)
{
    ctx.registerFunc<char>("char_func", ContextTest::charFunc);
    EXPECT_THAT(ctx.get<char>("char_func"), IsValue('b'));
}

TEST_F(ContextTest, get_wrong_type_value)
{
    ctx.registerValue("wrong_type", 1);
    EXPECT_THAT(ctx.get<string>("wrong_type"), IsError(Context::Error::NO_VALUE));
}

TEST_F(ContextTest, get_wrong_key_name)
{
    ctx.registerValue("wrong_key", 1);
    EXPECT_THAT(ctx.get<int>("wrong_keyy"), IsError(Context::Error::NO_VALUE));
}

TEST_F(ContextTest, unregister_key_of_value)
{
    ctx.registerValue("new_value_key", 1);
    ctx.unregisterKey<int>("new_value_key");
    EXPECT_THAT(ctx.get<int>("new_value_key"), IsError(Context::Error::NO_VALUE));
}

TEST_F(ContextTest, unregister_key_of_func)
{
    ctx.registerFunc<int>("new_func_key", maybeIntFunc);
    ctx.unregisterKey<int>("new_func_key");
    EXPECT_THAT(ctx.get<int>("new_func_key"), IsError(Context::Error::NO_VALUE));
}

TEST(ParamTest, matching)
{
    using namespace EnvKeyAttr;

    ParamAttr empty;
    ParamAttr verb1(Verbosity::LOW);
    ParamAttr verb2(Verbosity::HIGH);
    ParamAttr log(LogSection::SOURCE);
    ParamAttr both1(LogSection::SOURCE, Verbosity::LOW);
    ParamAttr both2(Verbosity::LOW, LogSection::SOURCE);
    ParamAttr both3(LogSection::SOURCE, Verbosity::HIGH);


    EXPECT_TRUE(empty.doesMatch(empty));
    EXPECT_TRUE(verb1.doesMatch(empty));
    EXPECT_TRUE(log.doesMatch(empty));
    EXPECT_TRUE(both1.doesMatch(empty));

    EXPECT_FALSE(empty.doesMatch(verb1));
    EXPECT_FALSE(empty.doesMatch(log));
    EXPECT_FALSE(empty.doesMatch(both1));

    EXPECT_TRUE(verb1.doesMatch(verb1));
    EXPECT_TRUE(both1.doesMatch(verb1));

    EXPECT_FALSE(verb2.doesMatch(verb1));
    EXPECT_FALSE(log.doesMatch(verb1));
    EXPECT_FALSE(both3.doesMatch(verb1));

    EXPECT_TRUE(both1.doesMatch(log));
    EXPECT_TRUE(both1.doesMatch(both1));
    EXPECT_TRUE(both1.doesMatch(both2));

    EXPECT_FALSE(both1.doesMatch(both3));
}
