#include "environment.h"
#include "cptest.h"
#include "mock/mock_rest_api.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

class EnvRestTest : public Test
{
public:
    EnvRestTest()
    {
        EXPECT_CALL(mock_rs, mockRestCall(RestAction::ADD, "declare-boolean-variable", _))
            .WillOnce(WithArg<2>(Invoke(this, &EnvRestTest::declareVariable)));
        env.preload();
        env.init();
        i_env = Singleton::Consume<I_Environment>::from(env);
    }

    unique_ptr<ServerRest> declare_variable;
    I_Environment *i_env;

private:
    bool declareVariable(const unique_ptr<RestInit> &p) { declare_variable = p->getRest(); return true; }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
    StrictMock<MockRestApi> mock_rs;
};

static ostream & operator<<(ostream &os, const Context::Error &) { return os; }

TEST_F(EnvRestTest, declare_variable)
{
    EXPECT_THAT(i_env->get<bool>("true_val"), IsError(Context::Error::NO_VALUE));

    stringstream is;
    is << "{\"name\": \"true_val\", \"expr\": \"All()\"}";
    auto output = declare_variable->performRestCall(is);

    EXPECT_THAT(output, IsValue(""));

    EXPECT_THAT(i_env->get<bool>("true_val"), IsValue(true));
}

TEST_F(EnvRestTest, no_expr)
{
    stringstream is;
    is << "{\"name\": \"true_val\"}";
    auto output = declare_variable->performRestCall(is);

    EXPECT_THAT(output, IsError("Couldn't get variable expr"));
}

TEST_F(EnvRestTest, no_name)
{
    stringstream is;
    is << "{\"expr\": \"All()\"}";
    auto output = declare_variable->performRestCall(is);

    EXPECT_THAT(output, IsError("Couldn't get variable name"));
}
