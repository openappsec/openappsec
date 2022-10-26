#include "environment.h"

#include "cptest.h"

using namespace testing;
using namespace std;

class EnvironmentTest : public Test
{
public:
    EnvironmentTest() { ctx.activate(); ctx2.activate(); }
    ~EnvironmentTest() { ctx2.deactivate(); ctx.deactivate(); }

    ::Environment env;
    I_Environment *i_env = Singleton::Consume<I_Environment>::from(env);
    Context ctx, ctx2;
};

class ConvertableToString
{
public:
    ConvertableToString(int _i, int _j) : i(_i), j(_j) {}

    int i, j;
};

ostream &
operator<<(ostream &os, const ConvertableToString &obj)
{
    return os << obj.i << "---" << obj.j;
}

TEST_F(EnvironmentTest, all_strings)
{
    string key_a = "A";
    string key_b = "B";
    string key_c = "C";
    string key_d = "D";
    string key_e = "E";
    string key_f = "F";
    string key_g = "G";

    string val_num = "123";
    string val_alpha = "abc";

    ctx.registerValue(key_a, val_num);
    ctx.registerValue(key_b, val_alpha, EnvKeyAttr::LogSection::SOURCE);
    ctx.registerValue(key_c, ConvertableToString(2, 9),  EnvKeyAttr::LogSection::DATA, EnvKeyAttr::Verbosity::LOW);
    ctx.registerValue(key_g, false, EnvKeyAttr::Verbosity::HIGH);
    ctx2.registerValue(key_d, ConvertableToString(5, 3), EnvKeyAttr::LogSection::DATA);
    ctx2.registerValue(key_e, 9);
    ctx2.registerValue(key_f, true);

    EXPECT_THAT(
        i_env->getAllStrings(),
        UnorderedElementsAre(
            make_pair(key_a, val_num),
            make_pair(key_b, val_alpha),
            make_pair(key_d, "5---3"),
            make_pair(key_c, "2---9")
        )
    );

    EXPECT_THAT(
        i_env->getAllStrings(EnvKeyAttr::Verbosity::HIGH),
        UnorderedElementsAre()
    );

    EXPECT_THAT(
        i_env->getAllStrings(EnvKeyAttr::LogSection::SOURCE),
        UnorderedElementsAre(
            make_pair(key_b, val_alpha)
        )
    );

    EXPECT_THAT(
        i_env->getAllStrings(EnvKeyAttr::LogSection::DATA),
        UnorderedElementsAre(
            make_pair(key_d, "5---3"),
            make_pair(key_c, "2---9")
        )
    );

    EXPECT_THAT(i_env->getAllUints(), UnorderedElementsAre(make_pair(key_e, 9)));

    EXPECT_THAT(i_env->getAllBools(), UnorderedElementsAre(make_pair(key_f, true), make_pair(key_g, false)));
}
