#include "buffer.h"
#include "cptest.h"
#include "cptest.h"
#include "environment.h"
#include "singleton.h"
#include "environment_evaluator.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

class BuffferEval : public Test
{
public:
    BuffferEval()
    {
        env.preload();
        Buffer::preload();
        env.init();
        auto i_env = Singleton::Consume<I_Environment>::from(env);
        i_env->getConfigurationContext().registerValue("buf_a", buf_a);
        i_env->getConfigurationContext().registerValue("buf_b", buf_b);
    }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
    Buffer buf_a{"aaa"};
    Buffer buf_b{"bbb"};
};

static ostream & operator<<(ostream &os, const Context::Error &) { return os; }

TEST_F(BuffferEval, compare)
{
    auto eval_eq = genEvaluator<bool>("EqualBuffer(Get(buf_a), Get(buf_a))");
    EXPECT_TRUE(eval_eq.ok());
    EXPECT_THAT((*eval_eq)(), IsValue(true));

    auto eval_nq = genEvaluator<bool>("EqualBuffer(Get(buf_a), Get(buf_b))");
    EXPECT_TRUE(eval_nq.ok());
    EXPECT_THAT((*eval_nq)(), IsValue(false));
}

TEST_F(BuffferEval, constant)
{
    auto const_a = genEvaluator<Buffer>("ConstantBuffer(aaa)");
    EXPECT_TRUE(const_a.ok());
    EXPECT_THAT((*const_a)(), IsValue(buf_a));
}
