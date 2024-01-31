#include "rest.h"
#include "cptest.h"

#include <sstream>

using namespace std;
using namespace testing;

class MustParamClientCheck : public ClientRest
{
public:
    C2S_PARAM(int, output_int);
    S2C_PARAM(int, input_int);
};

TEST(RestMustParam, normal_client_operation)
{
    MustParamClientCheck rest;
    rest.output_int = 3;
    EXPECT_THAT(rest.genJson(), IsValue("{\n    \"output_int\": 3\n}"));

    EXPECT_TRUE(rest.loadJson("{ \"input_int\" : 7 }"));
    EXPECT_EQ(rest.input_int, 7);
}

TEST(RestMustParam, client_missing_output_variable)
{
    MustParamClientCheck rest;
    EXPECT_THAT(rest.genJson(), IsError("Couldn't output variable output_int"));
}

TEST(RestMustParam, client_missing_input_variable)
{
    MustParamClientCheck rest;
    rest.output_int = 3;
    EXPECT_THAT(rest.genJson(), IsValue("{\n    \"output_int\": 3\n}"));

    EXPECT_FALSE(rest.loadJson("{}"));
}

class MustParamServerCheck : public ServerRest
{
public:
    void doCall() override { if (set_output) output_int = 9; }

    C2S_PARAM(int, input_int);
    S2C_PARAM(int, output_int);
    bool set_output = true;
};

TEST(RestMustParam, normal_server_operation)
{
    MustParamServerCheck rest;

    stringstream ss;
    ss << "{ \"input_int\": 5 }";

    EXPECT_THAT(rest.performRestCall(ss), IsValue("{\n    \"output_int\": 9\n}"));
    EXPECT_EQ(rest.input_int, 5);
    EXPECT_EQ(rest.output_int, 9);
}

TEST(RestMustParam, server_missing_input_variable)
{
    MustParamServerCheck rest;

    stringstream ss;
    ss << "{}";

    EXPECT_THAT(rest.performRestCall(ss), IsError("Couldn't get variable input_int"));
}

TEST(RestMustParam, server_missing_output_variable)
{
    MustParamServerCheck rest;
    rest.set_output = false;

    stringstream ss;
    ss << "{ \"input_int\": 5 }";
    EXPECT_THAT(rest.performRestCall(ss), IsError("Couldn't output variable output_int"));
}
