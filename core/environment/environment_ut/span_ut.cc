#include "environment/span.h"

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

class SpanTest : public Test
{
public:
    SpanTest()
    {
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_TRACE, Debug::DebugLevel::TRACE);
    }

    ~SpanTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    template <typename T>
    void
    getSpanValues(const T &span)
    {
        trace_id_str = span.getTraceId();
        span_id_str = span.getSpanId();
        prev_id_str = span.getPrevSpanId();
        type = span.getSpanContextType();
    }

    NiceMock<MockMainLoop> mock_mainloop;
    NiceMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
    stringstream debug_output;
    string trace_id = "4cc6bce7-4f68-42d6-94fc-e4127ac65ded";
    string prev_span_id = "4cc6bce7-4f68-42d6-94fc-e4127ac65fef";
    string trace_id_str;
    string span_id_str;
    string prev_id_str;
    Span::ContextType type = Span::ContextType::NEW;
};

TEST_F(SpanTest, newSpanInNewTraceTest)
{
    {
        Span span(trace_id);
        getSpanValues<Span>(span);
    }

    EXPECT_EQ(type, Span::ContextType::NEW);
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id "+ trace_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id_str));
}

TEST_F(SpanTest, newSpanTest)
{
    {
        Span span(trace_id, Span::ContextType::CHILD_OF, prev_span_id);
        getSpanValues<Span>(span);
    }

    EXPECT_EQ(type, Span::ContextType::CHILD_OF);
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type Child of"));
    EXPECT_THAT(debug_output.str(), HasSubstr("previous span id " + prev_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id_str));
}

TEST_F(SpanTest, newSpanWrapperTest)
{
    {
        SpanWrapper span(trace_id, Span::ContextType::CHILD_OF, prev_span_id);
        getSpanValues<SpanWrapper>(span);
    }

    EXPECT_EQ(type, Span::ContextType::CHILD_OF);
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type Child of"));
    EXPECT_THAT(debug_output.str(), HasSubstr("previous span id " + prev_id_str));
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id_str));
}
