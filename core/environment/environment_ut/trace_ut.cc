#include "environment/trace.h"

#include "cptest.h"
#include "environment.h"
#include "debug.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_TRACE);

class TraceTest : public Test
{
public:
    TraceTest()
    {
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_TRACE, Debug::DebugLevel::TRACE);
    }

    ~TraceTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
    stringstream debug_output;
};

TEST_F(TraceTest, defaultTraceTest)
{
    string trace_id;
    {
        Trace trace;
        trace_id = trace.getTraceId();
    }
    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
}

TEST_F(TraceTest, nonDefaultTraceTest)
{
    string trace_id("4cc6bce7-4f68-42d6-94fc-e4127ac65ded");
    string trace_id_str;
    {
        Trace trace(trace_id);
        trace_id_str = trace.getTraceId();
    }

    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
}
