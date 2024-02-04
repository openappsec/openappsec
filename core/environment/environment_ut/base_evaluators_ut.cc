#include "environment_evaluator.h"
#include "cptest.h"
#include "environment.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

class EvaluatorTest : public Test
{
public:
    EvaluatorTest() {
        env.preload();
        env.init();
    }

    ~EvaluatorTest() {
        env.fini();
    }

private:
    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
};

std::ostream & operator<<(std::ostream &os, const Context::Error &);

std::ostream &
operator<<(std::ostream &os, const std::function<Maybe<bool, Context::Error>()> &)
{
    return os;
}

TEST_F(EvaluatorTest, empty_all)
{
    auto eval = genEvaluator<bool>("All()");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, empty_any)
{
    auto eval = genEvaluator<bool>("Any()");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(false));
}

TEST_F(EvaluatorTest, not_true)
{
    auto eval = genEvaluator<bool>("Not(All())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(false));
}

TEST_F(EvaluatorTest, not_false)
{
    auto eval = genEvaluator<bool>("Not(Any())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, no_true_any)
{
    auto eval = genEvaluator<bool>("Any(Any(),Any(),Any())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(false));
}

TEST_F(EvaluatorTest, one_true_any)
{
    auto eval = genEvaluator<bool>("Any(Any(),All(),Any())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, one_false_all)
{
    auto eval = genEvaluator<bool>("All(All(),All(),Any())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(false));
}

TEST_F(EvaluatorTest, all_true_all)
{
    auto eval = genEvaluator<bool>("All(All(),All(),All())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, all_true_all_with_spaces)
{
    auto eval = genEvaluator<bool>("All(All()     ,  All(   )  ,All()    )");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, select_all_all)
{
    auto eval = genEvaluator<bool>("Select(All(),All())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, select_all_any)
{
    auto eval = genEvaluator<bool>("Select(All(),Any())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(true));
}

TEST_F(EvaluatorTest, select_any_all)
{
    auto eval = genEvaluator<bool>("Select(Any(),All())");
    EXPECT_TRUE(eval.ok());
    auto function = eval.unpack();
    EXPECT_THAT(function(), IsValue(false));
}

TEST_F(EvaluatorTest, empty_not)
{
    auto eval = genEvaluator<bool>("Not()");
    EXPECT_THAT(eval, IsError("Wrong number of parameters for 'Not'. Got 0 parameters instead of expected 1"));
}

TEST_F(EvaluatorTest, too_many_inputs_not)
{
    auto eval = genEvaluator<bool>("Not(Any(), Any())");
    EXPECT_THAT(eval, IsError("Wrong number of parameters for 'Not'. Got 2 parameters instead of expected 1"));
}

TEST_F(EvaluatorTest, malformed_evaluator_leading_comma)
{
    auto eval = genEvaluator<bool>("Any(, Any())");
    EXPECT_THAT(eval, IsError("Could not find the opening bracket in the string"));
}

TEST_F(EvaluatorTest, malformed_evaluator_fake_evaluator)
{
    auto eval = genEvaluator<bool>("Not(NOTHING())");
    EXPECT_THAT(eval, IsError("Evaluator 'NOTHING' doesn't exist for the required type"));
}

TEST_F(EvaluatorTest, malformed_evaluator_fake_evaluator2)
{
    auto eval = genEvaluator<bool>("All(Any(), NOTHING())");
    EXPECT_THAT(eval, IsError("Evaluator 'NOTHING' doesn't exist for the required type"));
}

TEST_F(EvaluatorTest, empty_get)
{
    auto eval = genEvaluator<bool>("Get()");
    EXPECT_THAT(eval, IsError("Wrong number of parameters for 'Get'. Got 0 parameters instead of expected 1"));
}

TEST_F(EvaluatorTest, empty_select)
{
    auto eval = genEvaluator<bool>("Select()");
    EXPECT_THAT(
        eval,
        IsError("Wrong number of parameters for 'Select'. Got 0 parameters instead of expected more than 2")
    );
}

TEST_F(EvaluatorTest, single_in_select)
{
    auto eval = genEvaluator<bool>("Select(one)");
    EXPECT_THAT(
        eval,
        IsError("Wrong number of parameters for 'Select'. Got 1 parameters instead of expected more than 2")
    );
}

TEST_F(EvaluatorTest, select_bad_evaluators)
{
    auto eval = genEvaluator<bool>("Select(X(),Y())");
    EXPECT_THAT(eval, IsError("Evaluator 'X' doesn't exist for the required type"));
}

TEST_F(EvaluatorTest, malformed_evaluator_within_parameter)
{
    auto eval = genEvaluator<bool>("Any(All(), Any(BOB()))");
    EXPECT_THAT(eval, IsError("Evaluator 'BOB' doesn't exist for the required type"));
}
