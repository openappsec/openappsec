#include "i_mainloop.h"
#include "mainloop.h"

#include <fcntl.h>
#include <chrono>

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_time_get.h"
#include "mock/mock_environment.h"
#include "mock/mock_messaging.h"
#include "mock/mock_agent_details.h"
#include "scope_exit.h"
#include "metric/all_metric_event.h"
#include "debug.h"

using namespace std;
using namespace testing;
using namespace chrono;

USE_DEBUG_FLAG(D_MAINLOOP);

class EndTest
{
};

class MainloopTest : public Test
{
public:
    MainloopTest()
    {
        EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(active_context));

        Debug::setUnitTestFlag(D_MAINLOOP, Debug::DebugLevel::DEBUG);
        Debug::setNewDefaultStdout(&capture_debug);
    }

    ~MainloopTest()
    {
        Debug::setUnitTestFlag(D_MAINLOOP, Debug::DebugLevel::INFO);
        Debug::setNewDefaultStdout(&cout);
        mainloop_comp.fini();
    }

    void
    expectPersistentMessage()
    {
        EXPECT_CALL(
            mock_msg,
            mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, _)
        ).Times(2).WillRepeatedly(
            WithArgs<1, 6>(
                Invoke(
                    [this](const string &req_body, MessageTypeTag tag)
                    {
                        EXPECT_TRUE(tag == MessageTypeTag::REPORT || tag == MessageTypeTag::METRIC);
                        if (tag == MessageTypeTag::REPORT) startup_report_body = req_body;
                        static bool should_throw = false;
                        if (should_throw) {
                            should_throw = false;
                            throw EndTest();
                        } else {
                            should_throw = true;
                        }

                        return string();
                    }
                )
            )
        );
    }

    I_Environment::ActiveContexts active_context;

    NiceMock<MockTimeGet>       mock_time;
    MainloopComponent           mainloop_comp;
    NiceMock<MockEnvironment>   mock_env;
    StrictMock<MockMessaging>   mock_msg;
    NiceMock<MockAgentDetails>  mock_agent_details;
    I_MainLoop                  *mainloop = Singleton::Consume<I_MainLoop>::from(mainloop_comp);
    ConfigComponent             conf;
    Config::I_Config            *config = nullptr;
    ostringstream               capture_debug;
    string                      startup_report_body;
    bool                        stop_test = false;
};


TEST_F(MainloopTest, do_nothing)
{
}

TEST_F(MainloopTest, start_with_nothing_to_do)
{
    mainloop->run();
}

TEST_F(MainloopTest, basic_metrics_check)
{
    string startup_body_sent;
    expectPersistentMessage();

    mainloop_comp.init();

    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        [this] ()
        {
            while (true) {
                mainloop->yield(true);
            }
        },
        "internal test cb",
        true
    );

    try {
        mainloop->run();
    } catch (...) {
    }
    AllMetricEvent all_mt_event;
    all_mt_event.setReset(false);
    all_mt_event.notify();


    string mainloop_str =
        "{\n"
        "    \"Metric\": \"Mainloop sleep time data\",\n"
        "    \"Reporting interval\": 600,\n"
        "    \"mainloopMaxTimeSliceSample\": 1000,\n"
        "    \"mainloopAvgTimeSliceSample\": 1000.0,\n"
        "    \"mainloopLastTimeSliceSample\": 1000,\n"
        "    \"mainloopMaxSleepTimeSample\": 1000,\n"
        "    \"mainloopAvgSleepTimeSample\": 1000.0,\n"
        "    \"mainloopLastSleepTimeSample\": 1000,\n"
        "    \"mainloopMaxStressValueSample\": 0,\n"
        "    \"mainloopAvgStressValueSample\": 0.0,\n"
        "    \"mainloopLastStressValueSample\": 0\n"
        "}";

    EXPECT_THAT(all_mt_event.performNamedQuery(), ElementsAre(Pair("Mainloop sleep time data", mainloop_str)));

    static const string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"\",\n"
        "        \"eventName\": \"Nano service successfully started\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"High\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {}\n"
        "    }\n"
        "}";

    EXPECT_EQ(startup_report_body, expected_message);
}

TEST_F(MainloopTest, no_sleep_time_metrics_check)
{
    mainloop_comp.preload();

    string startup_body_sent;
    expectPersistentMessage();

    chrono::microseconds time(0);
    EXPECT_CALL(
        mock_time,
        getMonotonicTime()
    ).WillRepeatedly(InvokeWithoutArgs([&]{ time += microseconds(3000); return time; } ));

    setConfiguration<int>(
        2,
        string("Mainloop"),
        string("Idle routine time slice")
    );

    mainloop_comp.init();
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        [this] ()
        {
            while (true) {
                mainloop->yield(true);
            }
        },
        "internal test cb",
        true
    );

    try {
        mainloop->run();
    } catch (...) {
    }
    AllMetricEvent all_mt_event;
    all_mt_event.setReset(false);
    all_mt_event.notify();

    string mainloop_str =
        "{\n"
        "    \"Metric\": \"Mainloop sleep time data\",\n"
        "    \"Reporting interval\": 600,\n"
        "    \"mainloopMaxTimeSliceSample\": 2,\n"
        "    \"mainloopAvgTimeSliceSample\": 2.0,\n"
        "    \"mainloopLastTimeSliceSample\": 2,\n"
        "    \"mainloopMaxSleepTimeSample\": 0,\n"
        "    \"mainloopAvgSleepTimeSample\": 0.0,\n"
        "    \"mainloopLastSleepTimeSample\": 0,\n"
        "    \"mainloopMaxStressValueSample\": 0,\n"
        "    \"mainloopAvgStressValueSample\": 0.0,\n"
        "    \"mainloopLastStressValueSample\": 0\n"
        "}";

    EXPECT_THAT(all_mt_event.query(), ElementsAre(mainloop_str));

    static const string expected_message =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"\",\n"
        "        \"eventName\": \"Nano service successfully started\",\n"
        "        \"eventSeverity\": \"Info\",\n"
        "        \"eventPriority\": \"High\",\n"
        "        \"eventType\": \"Event Driven\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"info\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"\",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {}\n"
        "    }\n"
        "}";

    EXPECT_EQ(startup_report_body, expected_message);
}

TEST(MainloopTestWithoutComponent, register_config)
{
    ConfigComponent config;

    StrictMock<MockTimeGet> mock_timer;
    MainloopComponent mainloop_comp;
    ::Environment env;

    env.preload();
    mainloop_comp.preload();
    env.init();

    string config_json =
        "{\n"
        "    \"Mainloop\": {\n"
        "        \"Idle routine time slice\": [\n"
        "            {\n"
        "                \"value\": 200\n"
        "            }\n"
        "        ]\n"
        "    }\n"
        "}\n";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(config)->loadConfiguration(ss);

    int time_slice = getConfigurationWithDefault<int>(100, "Mainloop", "Idle routine time slice");
    EXPECT_EQ(time_slice, 200);

    env.fini();
}

TEST_F(MainloopTest, call_single_cb)
{
    int num_called = 0;
    auto cb = [&num_called] () {
        num_called++;
    };

    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, cb, "call single cb test", true);
    mainloop->run();
    EXPECT_EQ(1, num_called);
}

TEST_F(MainloopTest, call_single_yield)
{
    int num_called = 0;
    auto ml = mainloop;
    auto cb = [&num_called, ml] () {
        num_called++;
        ml->yield(true);
        num_called++;
    };

    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, cb, "call_single_yield test", true);
    mainloop->run();
    EXPECT_EQ(2, num_called);
}

TEST_F(MainloopTest, stop_from_cb)
{
    bool dtor_called = false;
    auto stop_cb = [&dtor_called, this] () {
        auto scope_guard = make_scope_exit([&dtor_called] () { dtor_called = true; });
        mainloop->stop();
        ADD_FAILURE() << "Should stop before this";
    };

    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, stop_cb, "stop_from_cb test", true);
    mainloop->run();
    EXPECT_TRUE(dtor_called); // Verifying that we exited the routine cleanly, invoking the dtor
}

TEST_F(MainloopTest, stop_other_cb)
{
    int num_called = 0;
    auto stoped_cb = [&num_called] () { num_called++; };
    auto stop_id = mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Offline,
        stoped_cb,
        "stop_other_cb test - cb to stop",
        true
    );

    auto stopping_bc = [stop_id, this] () { mainloop->stop(stop_id); };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stopping_bc,
        "stop_other_cb test - cb that stops",
        true
    );

    mainloop->run();
    EXPECT_EQ(0, num_called);
}

TEST_F(MainloopTest, call_recurring_cb)
{
    int num_called = 0;
    auto cb = [&num_called, this] () {
        num_called++;
        if (num_called == 3) mainloop->stop();
    };

    mainloop->addRecurringRoutine(
        I_MainLoop::RoutineType::RealTime,
        chrono::microseconds(0),
        cb,
        "call_recurring_cb",
        true
    );
    mainloop->run();
    EXPECT_EQ(3, num_called);
}

TEST_F(MainloopTest, call_file_cb)
{
    CPTestTempfile file({ "a", "b", "c" });
    int fd = open(file.fname.c_str(), O_RDONLY);
    ASSERT_LT(0, fd);

    int num_called = 0;
    auto cb = [&num_called, fd, this] () {
        char ch;
        ASSERT_EQ(1, read(fd, &ch, 1));
        if (ch == 'c') mainloop->stop();
        num_called++;
    };
    mainloop->addFileRoutine(I_MainLoop::RoutineType::RealTime, fd, cb, "call_file_cb test", true);

    mainloop->run();
    EXPECT_EQ(4, num_called);
}

TEST_F(MainloopTest, stop_while_routines_are_running)
{
    int num_called = 0;
    auto routine = [&num_called] () {
        num_called++;
    };

    auto stop_cb = [this] () {
        mainloop->stopAll();
    };

    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        routine,
        "stop_while_routines_are_running test - cb to stop",
        true
    );
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Timer,
        stop_cb,
        "stop_while_routines_are_running test - cb that stops",
        true
    );
    mainloop->run();
    // "routine" is of higher priority than "stop", so it should run at least once before "stop" is called.
    EXPECT_LT(0, num_called);
}

TEST_F(MainloopTest, halt_self)
{
    int num_called = 0;
    auto routine = [&num_called, this] () {
        mainloop->halt();
        num_called++;
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        routine,
        "halt_self test - cb to stop",
        true
    );

    auto stop_cb = [this] () {
        mainloop->stopAll();
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        stop_cb,
        "halt_self test - cb that stops",
        true
    );

    mainloop->run();
    EXPECT_EQ(0, num_called);
}

TEST_F(MainloopTest, halt_resume)
{
    auto stop_cb = [this] () {
        mainloop->stopAll();
    };
    auto id = mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::Timer,
        stop_cb,
        "halt_resume test - cb that stops",
        true
    );

    int num_called = 0;
    auto routine = [&num_called, this, id] () {
        mainloop->halt(id);

        while (true) {
            if (num_called == 100)  mainloop->resume(id);
            num_called++;
            mainloop->yield(true);
        }
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        routine,
        "halt_resume test - cb to stop",
        true
    );

    mainloop->run();
    EXPECT_LT(100, num_called);
}

TEST_F(MainloopTest, death_on_run_twice)
{
    cptestPrepareToDie();
    auto cb = [this] () {
        EXPECT_DEATH(mainloop->run(), "MainloopComponent::Impl::run was called while it was already running");
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        cb,
        "death_on_run_twice test",
        true
    );

    mainloop->run();
}

TEST_F(MainloopTest, get_routine_id)
{
    cptestPrepareToDie();
    auto cb = [this] () {
        EXPECT_EQ(mainloop->getCurrentRoutineId().unpack(), 1);
        EXPECT_DEATH(mainloop->run(), "MainloopComponent::Impl::run was called while it was already running");
    };
    mainloop->addOneTimeRoutine(
        I_MainLoop::RoutineType::RealTime,
        cb,
        "get_routine_id test",
        true
    );

    mainloop->run();
}

TEST_F(MainloopTest, check_routine_name)
{
    int num_called = 0;
    auto cb = [&num_called] () {
        num_called++;
    };
    Debug::setUnitTestFlag(D_MAINLOOP, Debug::DebugLevel::TRACE);
    mainloop->addOneTimeRoutine(I_MainLoop::RoutineType::RealTime, cb, "check routine name test", true);
    EXPECT_THAT(capture_debug.str(), HasSubstr("Added new routine. Name: check routine name test"));
    mainloop->run();
    EXPECT_THAT(
        capture_debug.str(),
        HasSubstr("Starting execution of corutine. Routine named: check routine name test")
    );
}
