#include "environment.h"

#include "cptest.h"
#include "i_mainloop.h"
#include "mainloop.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_time_get.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_messaging.h"
#include "mock/mock_agent_details.h"
#include "config.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_TRACE);
USE_DEBUG_FLAG(D_METRICS);

class TracingTest : public Test
{
public:
    TracingTest()
    {
        env.preload();
        i_env = Singleton::Consume<I_Environment>::from(env);
        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_TRACE, Debug::DebugLevel::TRACE);
        Debug::setUnitTestFlag(D_METRICS, Debug::DebugLevel::TRACE);
        setConfiguration<bool>(true, "environment", "enable tracing");
        setConfiguration<bool>(false, string("metric"), string("fogMetricSendEnable"));
        EXPECT_CALL(mock_mainloop, addRecurringRoutine(I_MainLoop::RoutineType::System, _, _, _, _))
            .WillOnce(DoAll(SaveArg<2>(&routine), Return(0)));
        env.init();
    }

    ~TracingTest()
    {
        Debug::setNewDefaultStdout(&cout);
    }

    I_MainLoop::Routine routine;
    StrictMock<MockMainLoop>  mock_mainloop;
    StrictMock<MockTimeGet> mock_timer;
    ConfigComponent conf;
    ::Environment env;
    I_Environment *i_env;
    stringstream debug_output;
};

TEST_F(TracingTest, noTraceTest)
{
    auto empty_trace = i_env->getCurrentTrace();
    EXPECT_EQ("", empty_trace);

    auto empty_span = i_env->getCurrentSpan();
    EXPECT_EQ("", empty_span);
}

TEST_F(TracingTest, disabledTraces)
{
    setConfiguration<bool>(false, "environment", "enable tracing");
    env.init();

    i_env->startNewTrace();
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_EQ("", i_env->getCurrentSpan());
    EXPECT_EQ("", i_env->getCurrentTrace());

    EXPECT_EQ("", debug_output.str());

    i_env->finishSpan();
    EXPECT_EQ("", debug_output.str());
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->finishTrace();
    EXPECT_EQ("", debug_output.str());
    EXPECT_EQ("", i_env->getCurrentTrace());
}

TEST_F(TracingTest, newTraceSpanTest)
{
    i_env->startNewTrace();
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_NE("", i_env->getCurrentSpan());
    EXPECT_NE("", i_env->getCurrentTrace());

    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
    EXPECT_THAT(debug_output.str(), HasSubstr(", trace id " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr(", context type New"));

    i_env->finishSpan();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 1"));

    i_env->finishTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 0"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"maxSpanPerTrace\": 1"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"avgSpanPerTrace\": 1.0"));
}

TEST_F(TracingTest, newSpanScopeTest)
{
    string trace_id;
    string span_id;
    i_env->startNewTrace(false);
    EXPECT_NE("", i_env->getCurrentTrace());
    EXPECT_EQ("", i_env->getCurrentSpan());
    trace_id = i_env->getCurrentTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    {
        auto span_scope = i_env->startNewSpanScope(Span::ContextType::NEW);
        span_id = i_env->getCurrentSpan();
        EXPECT_NE("", i_env->getCurrentSpan());
        EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
        EXPECT_THAT(debug_output.str(), HasSubstr(", trace id " + trace_id));
        EXPECT_THAT(debug_output.str(), HasSubstr(", context type New"));
        EXPECT_NE("", i_env->getCurrentSpan());
    }
    EXPECT_EQ("", i_env->getCurrentSpan());
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));

    i_env->finishTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 0"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"maxSpanPerTrace\": 1"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"avgSpanPerTrace\": 1.0"));
}

TEST_F(TracingTest, oldTraceNewSpanTest)
{
    i_env->startNewTrace(true, "a687b388-1108-4083-9852-07c33b1074e9");
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_EQ(trace_id, "a687b388-1108-4083-9852-07c33b1074e9");
    EXPECT_NE("", i_env->getCurrentSpan());
    EXPECT_NE("", i_env->getCurrentTrace());

    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));

    i_env->finishSpan();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->finishTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());
}

TEST_F(TracingTest, finishSpecificTraceSpan)
{
    i_env->startNewTrace(true, "a687b388-1108-4083-9852-07c33b1074e9");
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_EQ(trace_id, "a687b388-1108-4083-9852-07c33b1074e9");
    EXPECT_NE("", i_env->getCurrentSpan());
    EXPECT_NE("", i_env->getCurrentTrace());

    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));

    i_env->finishSpan(span_id);
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->finishTrace(trace_id);
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());
}


TEST_F(TracingTest, 2SpansSameFlow)
{
    i_env->startNewTrace(true, "a687b388-1108-4083-9852-07c33b1074e9");
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_EQ(trace_id, "a687b388-1108-4083-9852-07c33b1074e9");
    EXPECT_NE("", i_env->getCurrentSpan());
    EXPECT_NE("", i_env->getCurrentTrace());

    EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));

    i_env->finishSpan();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->startNewSpan(Span::ContextType::FOLLOWS_FROM, span_id);
    auto another_span_id = i_env->getCurrentSpan();
    EXPECT_EQ(trace_id, i_env->getCurrentTrace());
    EXPECT_NE(another_span_id, span_id);

    EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + another_span_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id));
    EXPECT_THAT(debug_output.str(), HasSubstr("context type Follows from"));

    i_env->finishSpan();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + another_span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->finishTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 0"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"maxSpanPerTrace\": 2"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"avgSpanPerTrace\": 2.0"));
}

TEST_F(TracingTest, metricTracingTest)
{
    i_env->startNewTrace();
    auto span_id = i_env->getCurrentSpan();

    i_env->finishSpan();

    i_env->startNewSpan(Span::ContextType::FOLLOWS_FROM, span_id);
    auto another_span_id = i_env->getCurrentSpan();
    i_env->finishSpan();

    i_env->startNewSpan(Span::ContextType::FOLLOWS_FROM, another_span_id);
    i_env->finishSpan();
    i_env->finishTrace();

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 0"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"maxSpanPerTrace\": 3"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"avgSpanPerTrace\": 3.0"));


    i_env->startNewTrace();
    i_env->finishSpan();
    i_env->finishTrace();

    routine();
    EXPECT_THAT(debug_output.str(), HasSubstr("\"Metric\": \"tracing\""));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"currentTraceNumber\": 0"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"maxSpanPerTrace\": 3"));
    EXPECT_THAT(debug_output.str(), HasSubstr("\"avgSpanPerTrace\": 2.0"));
}

class TracingCompRoutinesTest : public Test
{
public:
    TracingCompRoutinesTest()
    {
        env.preload();
        setConfiguration<bool>(true, "environment", "enable tracing");
        env.init();
        mainloop_comp.init();

        mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
        i_env = Singleton::Consume<I_Environment>::from(env);

        Debug::setNewDefaultStdout(&debug_output);
        Debug::setUnitTestFlag(D_TRACE, Debug::DebugLevel::TRACE);

        I_MainLoop::Routine another_routine = [&] () {
            while (!stop) {
                mainloop->yield(true);
            }

            i_env->startNewTrace(true, "a687b388-1108-4083-9852-07c33b107589");
            auto another_trace_id = i_env->getCurrentTrace();
            auto another_span_id = i_env->getCurrentSpan();

            EXPECT_NE(trace_id, another_trace_id);
            EXPECT_NE(span_id, another_span_id);
            EXPECT_NE("", i_env->getCurrentSpan());
            EXPECT_NE("", i_env->getCurrentTrace());

            EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + another_trace_id));

            EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + another_span_id));
            EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + another_trace_id));
            EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));

            i_env->finishSpan();
            EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + another_span_id));
            EXPECT_EQ("", i_env->getCurrentSpan());

            i_env->finishTrace();
            EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + another_trace_id));
            EXPECT_EQ("", i_env->getCurrentTrace());
        };
        mainloop->addOneTimeRoutine(
            I_MainLoop::RoutineType::RealTime,
            another_routine,
            "TracingCompRoutinesTest routine",
            true
        );
    }

    ~TracingCompRoutinesTest()
    {
        Debug::setNewDefaultStdout(&cout);
        mainloop_comp.fini();
    }

    bool stop = false;
    stringstream debug_output;
    ConfigComponent config;
    NiceMock<MockAgentDetails> agent_details_mocker;
    NiceMock<MockTimeGet> mock_time;
    NiceMock<MockMessaging> mock_messaging;
    MainloopComponent mainloop_comp;
    ::Environment env;
    I_MainLoop *mainloop;
    I_Environment *i_env;
    string trace_id;
    string span_id;
};

TEST_F(TracingCompRoutinesTest, 2SpansDifFlow)
{
    ON_CALL(mock_messaging, mockSendPersistentMessage(_, _, _, _, _, _, _)).WillByDefault(Return(string()));

    I_MainLoop::Routine routine = [&] () {
        i_env->startNewTrace(true, "a687b388-1108-4083-9852-07c33b1074e9");
        trace_id = i_env->getCurrentTrace();
        span_id = i_env->getCurrentSpan();
        string headers = i_env->getCurrentHeaders();
        EXPECT_THAT(headers, HasSubstr("X-Trace-Id: " + trace_id));
        EXPECT_THAT(headers, HasSubstr("X-Span-Id: " + span_id));

        EXPECT_EQ(trace_id, "a687b388-1108-4083-9852-07c33b1074e9");
        EXPECT_NE("", i_env->getCurrentSpan());
        EXPECT_NE("", i_env->getCurrentTrace());

        EXPECT_THAT(debug_output.str(), HasSubstr("New trace was created " + trace_id));

        EXPECT_THAT(debug_output.str(), HasSubstr("New span was created " + span_id));
        EXPECT_THAT(debug_output.str(), HasSubstr("trace id " + trace_id));
        EXPECT_THAT(debug_output.str(), HasSubstr("context type New"));

        stop = true;
        mainloop->yield(true);

        i_env->finishSpan();
        EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
        EXPECT_EQ("", i_env->getCurrentSpan());

        i_env->finishTrace();
        EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
        EXPECT_EQ("", i_env->getCurrentTrace());
    };

    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, routine, "2SpansDifFlow test routine");
    try {
        mainloop->run();
    } catch(...) {
    }
}
