#include "debug.h"

#include <sstream>
#include <string>
#include <fstream>
#include <vector>

#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_agent_details.h"
#include "instance_awareness.h"
#include "mock/mock_time_get.h"
#include "mock/mock_messaging.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_environment.h"
#include "mock/mock_instance_awareness.h"

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_INFRA);
USE_DEBUG_FLAG(D_FW);
USE_DEBUG_FLAG(D_PM);
USE_DEBUG_FLAG(D_PM_EXEC);
USE_DEBUG_FLAG(D_TRACE);
USE_DEBUG_FLAG(D_HTTP_REQUEST);

string line = "";

void doFWError() { dbgError(D_FW) << "FW error message"; line = to_string(__LINE__); }
void doFWWarning() { dbgWarning(D_FW) << "FW warning message"; line = to_string(__LINE__); }
void doFWInfo() { dbgInfo(D_FW) << "FW info message"; line = to_string(__LINE__); }
void doFWDebug() { dbgDebug(D_FW) << "FW debug message"; line = to_string(__LINE__); }
void doFWTrace() { dbgTrace(D_FW) << "FW trace message"; line = to_string(__LINE__); }
void doPMTrace() { dbgTrace(D_PM) << "PM trace message"; line = to_string(__LINE__); }
void doPMExecTrace() { dbgTrace(D_PM_EXEC) << "PM_EXEC trace message"; line = to_string(__LINE__); }

template <typename ...Args> void doManyFlags(Args ...args) { dbgDebug(args...) << "stab"; line = to_string(__LINE__); }

TEST(DebugBaseTest, death_on_panic)
{
    cptestPrepareToDie();

    EXPECT_DEATH(dbgAssert(1==2) << "Does your school teach otherwise?", "Does your school teach otherwise?");
}

TEST(DebugBaseTest, default_levels)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(),
        "[doFWInfo@debug_ut.cc:" + line + "                                      | ---] FW info message\n");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_error)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::ERROR);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(), "");

    doFWWarning();
    EXPECT_EQ(debug_output.str(), "");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_message)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::INFO);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(),
        "[doFWInfo@debug_ut.cc:" + line + "                                      | ---] FW info message\n");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_warning)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::WARNING);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_debug)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::DEBUG);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(),
        "[doFWInfo@debug_ut.cc:" + line + "                                      | ---] FW info message\n");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(),
        "[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n");
    debug_output.str("");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_trace)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::TRACE);

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(),
        "[doFWInfo@debug_ut.cc:" + line + "                                      | ---] FW info message\n");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(),
        "[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n");
    debug_output.str("");

    doFWTrace();
    EXPECT_EQ(debug_output.str(),
        "[doFWTrace@debug_ut.cc:" + line + "                                     | >>>] FW trace message\n");

    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::WARNING); // Reset debug level so it won't effect other tests
    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, set_flag_to_none)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::NONE);

    doFWError();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");

    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::WARNING); // Reset debug level so it won't effect other tests
    Debug::setNewDefaultStdout(&cout);
}
TEST(DebugBaseTest, testing_debug_levels)
{
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::DEBUG);
    EXPECT_TRUE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::ERROR));
    EXPECT_TRUE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::INFO));
    EXPECT_TRUE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::DEBUG));
    EXPECT_FALSE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::TRACE));
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::WARNING); // Reset debug level so it won't effect other tests
    EXPECT_TRUE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::ERROR));
    EXPECT_FALSE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::INFO));
    EXPECT_FALSE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::DEBUG));
    EXPECT_FALSE(Debug::isFlagAtleastLevel(D_FW, Debug::DebugLevel::TRACE));
}

TEST(DebugBaseTest, newTraceSpanDebugTest)
{
    StrictMock<MockTimeGet> mock_time;
    NiceMock<MockMainLoop> mock_mainloop;

    ConfigComponent conf;
    setConfiguration<bool>(true, "environment", "enable tracing");
    ::Environment env;
    env.preload();
    env.init();
    auto i_env = Singleton::Consume<I_Environment>::from(env);
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));

    Maybe<I_MainLoop::RoutineID> error_id = genError("no id");
    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillRepeatedly(Return(error_id));
    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_TRACE, Debug::DebugLevel::TRACE);

    i_env->startNewTrace();
    auto trace_id = i_env->getCurrentTrace();
    auto span_id = i_env->getCurrentSpan();

    EXPECT_NE("", i_env->getCurrentSpan());
    EXPECT_NE("", i_env->getCurrentTrace());

    string trace_output = "[2016-11-13T17:31:24.087: " + trace_id.substr(0, 6) + ": "
        + "Trace@trace.cc:36 "
        + "                                   | >>>] New trace was created "
        + trace_id;
    EXPECT_THAT(debug_output.str(), HasSubstr(trace_output));

    string span_output = "[2016-11-13T17:31:24.087: "
        + trace_id.substr(0, 6)
        + "-"
        + span_id.substr(0, 6)
        + ": Span@span.cc:49 "
        + "                              | >>>] New span was created "
        + span_id
        + ", trace id "
        + trace_id
        + ", context type New";
    EXPECT_THAT(debug_output.str(), HasSubstr(span_output));

    i_env->finishSpan();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current span has ended " + span_id));
    EXPECT_EQ("", i_env->getCurrentSpan());

    i_env->finishTrace();
    EXPECT_THAT(debug_output.str(), HasSubstr("Current trace has ended " + trace_id));
    EXPECT_EQ("", i_env->getCurrentTrace());
    Debug::setNewDefaultStdout(&cout);
    Debug::fini();
}

TEST(DebugBaseTest, add_timestamp)
{
    StrictMock<MockEnvironment> mock_env;
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    StrictMock<MockTimeGet> mock_time;
    StrictMock<MockMainLoop> mock_mainloop;
    EXPECT_CALL(mock_time, getWalltimeStr()).WillOnce(Return(string("2016-11-13T17:31:24.087")));

    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillOnce(Return(5));
    string trace_id("a687b388-1108-4083-9852-07c33b1074e9");
    string span_id("4cc6bce7-4f68-42d6-94fc-e4127ac65fef");
    EXPECT_CALL(mock_env, getCurrentTrace()).WillOnce(Return(trace_id));
    EXPECT_CALL(mock_env, getCurrentSpan()).WillOnce(Return(string(span_id)));

    Context context;
    I_Environment::ActiveContexts active_context({&context}, true);
    EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(active_context));

    Debug::init();

    doFWError();
    string expected_output =
        "[2016-11-13T17:31:24.087: " +
        trace_id.substr(0, 6) +
        "-" +
        span_id.substr(0, 6) +
        ": <" +
        to_string(5) +
        "> doFWError@debug_ut.cc:" +
        line +
        "                  | !!!] FW error message\n";

    EXPECT_EQ(debug_output.str(), expected_output);

    Debug::setNewDefaultStdout(&cout);
    Debug::fini();
}

TEST(DebugBaseTest, multi_flag_debugs)
{
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::TRACE);

    doManyFlags(D_FW, D_INFRA);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_INFRA, D_FW);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_FW, D_INFRA, D_PM);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_INFRA, D_FW, D_PM);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_FW, D_INFRA, D_PM, D_PM_EXEC);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_INFRA, D_FW, D_PM, D_PM_EXEC);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_INFRA, D_PM, D_FW, D_PM_EXEC);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    doManyFlags(D_INFRA, D_PM, D_PM_EXEC, D_FW);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    Debug::setUnitTestFlag(D_INFRA, Debug::DebugLevel::TRACE);

    doManyFlags(D_FW, D_INFRA);
    EXPECT_EQ(debug_output.str(),
        "[doManyFlags@debug_ut.cc:" + line + "                                   | @@@] stab\n");
    debug_output.str("");

    // Reset debug levels so it won't effect other tests
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::WARNING);
    Debug::setUnitTestFlag(D_INFRA, Debug::DebugLevel::WARNING);
    Debug::setNewDefaultStdout(&cout);
}

TEST(DebugBaseTest, failOpenDebugModeTest)
{
    StrictMock<MockMainLoop> mock_mainloop;
    StrictMock<MockTimeGet> mock_time;
    NiceMock<MockEnvironment> mock_env;

    Context context;
    I_Environment::ActiveContexts active_context({&context}, true);
    EXPECT_CALL(mock_env, getActiveContexts()).WillRepeatedly(ReturnRef(active_context));

    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::ERROR);

    Maybe<I_MainLoop::RoutineID> error_id = genError("no id");
    EXPECT_CALL(mock_mainloop, getCurrentRoutineId()).WillRepeatedly(Return(error_id));
    EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(chrono::microseconds(1)));
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[2016-11-13T17:31:24.087: : doFWError@debug_ut.cc:"
        + line
        + "                                   | !!!] FW error message\n");
    debug_output.str("");

    doFWInfo();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    I_MainLoop::Routine cb = nullptr;
    EXPECT_CALL(mock_mainloop, addOneTimeRoutine(_, _, _, _)).WillOnce(DoAll(SaveArg<1>(&cb), Return(0)));

    EXPECT_CALL(mock_mainloop, yield(A<chrono::microseconds>()))
        .WillOnce(
            Invoke(
                [&] (chrono::microseconds duration)
                {
                    EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(5)).count());
                    doFWError();
                    EXPECT_EQ(debug_output.str(),
                        "[2016-11-13T17:31:24.087: : doFWError@debug_ut.cc:"
                        + line
                        + "                                   | !!!] FW error message\n");
                    debug_output.str("");

                    doFWInfo();
                    EXPECT_EQ(debug_output.str(),
                        "[2016-11-13T17:31:24.087: : doFWInfo@debug_ut.cc:"
                        + line
                        + "                                    | ---] FW info message\n");
                    debug_output.str("");

                    doFWWarning();
                    EXPECT_EQ(debug_output.str(),
                        "[2016-11-13T17:31:24.087: : doFWWarning@debug_ut.cc:"
                        + line
                        + "                                 | ###] FW warning message\n");
                    debug_output.str("");

                    doFWDebug();
                    EXPECT_EQ(debug_output.str(),
                        "[2016-11-13T17:31:24.087: : doFWDebug@debug_ut.cc:"
                        + line
                        + "                                   | @@@] FW debug message\n");
                    debug_output.str("");

                    doFWTrace();
                    EXPECT_EQ(debug_output.str(),
                        "[2016-11-13T17:31:24.087: : doFWTrace@debug_ut.cc:"
                        + line
                        + "                                   | >>>] FW trace message\n");
                    debug_output.str("");
                }
            )
        );
    Debug::failOpenDebugMode(chrono::seconds(5));
    cb();

    doFWInfo();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_EQ(debug_output.str(), "");
    debug_output.str("");

    doFWError();
    EXPECT_EQ(debug_output.str(),
        "[2016-11-13T17:31:24.087: : doFWError@debug_ut.cc:"
        + line
        + "                                   | !!!] FW error message\n");
    debug_output.str("");

    Debug::setNewDefaultStdout(&cout);
    Debug::fini();
}

class DebugConfigTest : public Test
{
public:
    DebugConfigTest()
    {
        EXPECT_CALL(mock_agent_details, getAgentId()).WillRepeatedly(Return("Unknown"));
        EXPECT_CALL(mock_agent_details, getOrchestrationMode()).WillRepeatedly(Return(OrchestrationMode::ONLINE));
        Debug::preload();
        Debug::setNewDefaultStdout(&capture_debug);
    }


    ~DebugConfigTest()
    {
        loadConfiguration("");
        Debug::setNewDefaultStdout(&cout);
    }

    string
    getDebugMessage()
    {
        auto msg = capture_debug.str();
        capture_debug.str("");
        return msg;
    }

    bool
    loadConfiguration(const string &conf_str)
    {
        stringstream configuration;
        configuration << "{ \"Debug\": [ { \"Streams\": [" << conf_str << "] } ] }";
        return Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration);
    }

    void
    loadConfigurationWithOverrides(const string &conf_str, const string &override_str)
    {
        stringstream configuration;
        configuration << "{ \"agentSettings\": [" << override_str << "], ";
        configuration << "\"Debug\": [ { \"Streams\": [" << conf_str << "] } ] }";
        Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(configuration);
    }

    ConfigComponent conf;
    ::Environment env;
    stringstream capture_debug;
    StrictMock<MockAgentDetails> mock_agent_details;
};

TEST_F(DebugConfigTest, basic_configuration)
{
    loadConfiguration("{\"Output\": \"STDOUT\"}");

    doFWError();
    EXPECT_EQ(getDebugMessage(),
        "[doFWError@debug_ut.cc:" + line + "                                     | !!!] FW error message\n");

    doFWInfo();
    EXPECT_EQ(getDebugMessage(),
        "[doFWInfo@debug_ut.cc:" + line + "                                      | ---] FW info message\n");

    doFWWarning();
    EXPECT_EQ(getDebugMessage(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");

    doFWDebug();
    EXPECT_EQ(getDebugMessage(), "");

    doFWTrace();
    EXPECT_EQ(getDebugMessage(), "");
}

TEST_F(DebugConfigTest, hireracy)
{
    loadConfiguration("{\"Output\": \"STDOUT\", \"D_PM\": \"Trace\"}");

    doFWWarning();
    EXPECT_EQ(getDebugMessage(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");

    doFWDebug();
    EXPECT_EQ(getDebugMessage(), "");

    doPMTrace();
    EXPECT_EQ(getDebugMessage(),
        "[doPMTrace@debug_ut.cc:" + line + "                                     | >>>] PM trace message\n");

    doPMExecTrace();
    EXPECT_EQ(getDebugMessage(),
        "[doPMExecTrace@debug_ut.cc:" + line + "                                 | >>>] PM_EXEC trace message\n");
}

TEST_F(DebugConfigTest, debug_all)
{
    CPTestTempfile debug_file;

    loadConfiguration("{\"Output\": \"STDOUT\", \"D_PM\": \"Error\", \"D_ALL\": \"Trace\"}");

    doFWWarning();
    EXPECT_EQ(getDebugMessage(),
        "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n");

    doFWDebug();
    EXPECT_EQ(getDebugMessage(),
        "[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n");

    // D_PM is explicitly indicated with its level and thus overrides D_ALL
    doPMTrace();
    EXPECT_EQ(getDebugMessage(), "");

    doPMExecTrace();
    EXPECT_EQ(getDebugMessage(), "");
}

TEST_F(DebugConfigTest, two_streams)
{
    CPTestTempfile debug_file;

    loadConfiguration(
        "{\"Output\": \"STDOUT\", \"D_FW\": \"Trace\"},"
        "{\"Output\": \"" + debug_file.fname + "\", \"D_PM\": \"Trace\"}"
    );

    doFWTrace();
    EXPECT_EQ(getDebugMessage(),
        "[doFWTrace@debug_ut.cc:" + line + "                                     | >>>] FW trace message\n");

    doPMTrace();
    EXPECT_EQ(debug_file.readFile(),
        "[doPMTrace@debug_ut.cc:" + line + "                                     | >>>] PM trace message\n");
}

TEST_F(DebugConfigTest, file_steam_instance_awareness)
{
    string debug_file = "/tmp/cptest_temp_file_random_x_";
    string id = "073b8744b4c5-11";
    StrictMock<MockInstanceAwareness> mock_aware;
    EXPECT_CALL(mock_aware, getUniqueID(_)).WillOnce(Return(id));

    loadConfiguration("{\"Output\": \"" + debug_file + "\", \"D_PM\": \"Trace\"}");

    doPMTrace();

    const string new_debug_file = debug_file + id;

    ifstream text_file(new_debug_file);
    EXPECT_TRUE(text_file.is_open());
    stringstream buffer;
    buffer << text_file.rdbuf();

    text_file.close();
    remove(new_debug_file.c_str());

    EXPECT_EQ(buffer.str(),
        "[doPMTrace@debug_ut.cc:" + line + "                                     | >>>] PM trace message\n");
}

TEST_F(DebugConfigTest, override_configuration)
{
    conf.preload();
    string debug_config = "{\"Output\": \"STDOUT\", \"D_FW\": \"Trace\"}";
    loadConfiguration(debug_config);

    doFWWarning();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr(
            "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n"
        )
    );

    doFWDebug();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr("[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n")
    );

    doFWTrace();
    EXPECT_THAT(getDebugMessage(),
        HasSubstr("[doFWTrace@debug_ut.cc:" + line + "                                     | >>>] FW trace message\n")
    );

    string debug_override = "{\"id\": \"123-abc\", \"key\": \"agent.debug.flag.fw\", \"value\": \"debug\"}";
    loadConfigurationWithOverrides(debug_config, debug_override);

    doFWWarning();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr(
            "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n"
        )
    );

    doFWDebug();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr("[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n")
    );

    doFWTrace();
    EXPECT_EQ(getDebugMessage(), "");

    debug_config = "{\"Output\": \"STDOUT\", \"D_FW\": \"Debug\"}";
    debug_override = "{\"key\": \"agent.debug.flag.fw\", \"value\": \"trace\"}";
    loadConfigurationWithOverrides(debug_config, debug_override);

    doFWWarning();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr(
            "[doFWWarning@debug_ut.cc:" + line + "                                   | ###] FW warning message\n"
        )
    );

    doFWDebug();
    EXPECT_THAT(
        getDebugMessage(),
        HasSubstr("[doFWDebug@debug_ut.cc:" + line + "                                     | @@@] FW debug message\n")
    );

    doFWTrace();
    EXPECT_THAT(getDebugMessage(),
        HasSubstr("[doFWTrace@debug_ut.cc:" + line + "                                     | >>>] FW trace message\n")
    );

    debug_override = "{\"key\": \"agent.debug.stream.file\", \"value\": \"false\"}";
    loadConfigurationWithOverrides(debug_config, debug_override);

    doFWWarning();
    EXPECT_EQ(getDebugMessage(), "");

    doFWDebug();
    EXPECT_EQ(getDebugMessage(), "");

    doFWTrace();
    EXPECT_EQ(getDebugMessage(), "");
}

TEST_F(DebugConfigTest, fail_configuration)
{
    conf.preload();
    Debug::preload();
    string debug_config = "{\"Output\": \"STDOUT\", \"D_FW\": \"Jrace\"}";
    EXPECT_FALSE(loadConfiguration(debug_config));
}

ACTION(InvokeMainLoopCB)
{
    arg1();
}

TEST(DebugFogTest, fog_stream)
{
    ConfigComponent conf;
    ::Environment env;
    env.preload();
    env.init();
    stringstream capture_debug;
    conf.preload();

    StrictMock<MockMainLoop> mock_mainloop;
    StrictMock<MockTimeGet> mock_time;
    StrictMock<MockAgentDetails> mock_agent_details;
    EXPECT_CALL(mock_agent_details, getAgentId()).WillRepeatedly(Return("Unknown"));
    EXPECT_CALL(mock_agent_details, getOrchestrationMode()).WillRepeatedly(Return(OrchestrationMode::ONLINE));

    EXPECT_CALL(mock_time, getWalltimeStr(_)).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
    I_MainLoop::Routine send_debug_routine = nullptr;

    EXPECT_CALL(mock_mainloop, addRecurringRoutine(_, _, _, _, _))
        .WillOnce(DoAll(SaveArg<2>(&send_debug_routine), Return(0)));

    StrictMock<MockMessaging> messaging_mock;
    string message_body;
    EXPECT_CALL(messaging_mock, mockSendPersistentMessage(
        false,
        _,
        _,
        "/api/v1/agents/events/bulk",
        _,
        _,
        MessageTypeTag::DEBUG
    )).WillRepeatedly(DoAll(SaveArg<1>(&message_body), Return(Maybe<string>(string("")))));

    Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(
        vector<string>{"--orchestration-mode=online_mode"}
    );
    Debug::preload();
    string config_json =
        "{"
        "    \"Debug I/S\": {"
        "        \"Sent debug bulk size\": ["
        "            {"
        "                \"value\": 2"
        "            }"
        "        ]"
        "    },"
        "    \"Debug\": [{"
        "        \"Streams\": ["
        "            {"
        "                \"Output\": \"FOG\""
        "            }"
        "        ]"
        "    }]"
        "}";

    istringstream ss(config_json);
    Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(ss);

    doFWError();
    auto line1 = line;
    doFWWarning();

    string expected_message =
            "{\n"
            "    \"logs\": [\n"
            "        {\n"
            "            \"id\": 1,\n"
            "            \"log\": {\n"
            "                \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
            "                \"eventName\": \"Debug message\",\n"
            "                \"eventSeverity\": \"High\",\n"
            "                \"eventPriority\": \"Low\",\n"
            "                \"eventType\": \"Code Related\",\n"
            "                \"eventLevel\": \"Log\",\n"
            "                \"eventLogLevel\": \"error\",\n"
            "                \"eventAudience\": \"Internal\",\n"
            "                \"eventAudienceTeam\": \"\",\n"
            "                \"eventFrequency\": 0,\n"
            "                \"eventTags\": [\n"
            "                    \"Informational\"\n"
            "                ],\n"
            "                \"eventSource\": {\n"
            "                    \"agentId\": \"Unknown\",\n"
            "                    \"issuingFunction\": \"doFWError\",\n"
            "                    \"issuingFile\": \"debug_ut.cc\",\n"
            "                    \"issuingLine\": " + line1 + ",\n"
            "                    \"eventTraceId\": \"\",\n"
            "                    \"eventSpanId\": \"\",\n"
            "                    \"issuingEngineVersion\": \"\",\n"
            "                    \"serviceName\": \"Unnamed Nano Service\"\n"
            "                },\n"
            "                \"eventData\": {\n"
            "                    \"eventMessage\": \"FW error message\"\n"
            "                }\n"
            "            }\n"
            "        },\n"
            "        {\n"
            "            \"id\": 2,\n"
            "            \"log\": {\n"
            "                \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
            "                \"eventName\": \"Debug message\",\n"
            "                \"eventSeverity\": \"Medium\",\n"
            "                \"eventPriority\": \"Low\",\n"
            "                \"eventType\": \"Code Related\",\n"
            "                \"eventLevel\": \"Log\",\n"
            "                \"eventLogLevel\": \"warning\",\n"
            "                \"eventAudience\": \"Internal\",\n"
            "                \"eventAudienceTeam\": \"\",\n"
            "                \"eventFrequency\": 0,\n"
            "                \"eventTags\": [\n"
            "                    \"Informational\"\n"
            "                ],\n"
            "                \"eventSource\": {\n"
            "                    \"agentId\": \"Unknown\",\n"
            "                    \"issuingFunction\": \"doFWWarning\",\n"
            "                    \"issuingFile\": \"debug_ut.cc\",\n"
            "                    \"issuingLine\": " + line + ",\n"
            "                    \"eventTraceId\": \"\",\n"
            "                    \"eventSpanId\": \"\",\n"
            "                    \"issuingEngineVersion\": \"\",\n"
            "                    \"serviceName\": \"Unnamed Nano Service\"\n"
            "                },\n"
            "                \"eventData\": {\n"
            "                    \"eventMessage\": \"FW warning message\"\n"
            "                }\n"
            "            }\n"
            "        }\n"
            "    ]\n"
            "}";

    send_debug_routine();

    EXPECT_EQ(message_body, expected_message);

    setConfiguration<uint>(3, string("Debug I/S"), string("Threshold debug bulk size"));
    doFWError();
    doFWError();
    doFWError();

    expected_message =
        "{\n"
        "    \"logs\": [\n"
        "        {\n"
        "            \"id\": 1,\n"
        "            \"log\": {\n"
        "                \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "                \"eventName\": \"Debug message\",\n"
        "                \"eventSeverity\": \"Medium\",\n"
        "                \"eventPriority\": \"Low\",\n"
        "                \"eventType\": \"Code Related\",\n"
        "                \"eventLevel\": \"Log\",\n"
        "                \"eventLogLevel\": \"warning\",\n"
        "                \"eventAudience\": \"Internal\",\n"
        "                \"eventAudienceTeam\": \"\",\n"
        "                \"eventFrequency\": 0,\n"
        "                \"eventTags\": [\n"
        "                    \"Informational\"\n"
        "                ],\n"
        "                \"eventSource\": {\n"
        "                    \"agentId\": \"Unknown\",\n"
        "                    \"issuingFunction\": \"handleThresholdReach\",\n"
        "                    \"issuingFile\": \"debug_streams.cc\",\n"
        "                    \"issuingLine\": 345,\n"
        "                    \"eventTraceId\": \"\",\n"
        "                    \"eventSpanId\": \"\",\n"
        "                    \"issuingEngineVersion\": \"\",\n"
        "                    \"serviceName\": \"Unnamed Nano Service\"\n"
        "                },\n"
        "                \"eventData\": {\n"
        "                    \"eventMessage\": \"Threshold bulk size was reached, 3 debug messages were discarded\"\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    ]\n"
        "}";

    send_debug_routine();
    EXPECT_EQ(message_body, expected_message);

    setConfiguration<bool>(false, string("Debug I/S"), string("Enable bulk of debugs"));

    EXPECT_CALL(mock_mainloop, addOneTimeRoutine(_, _, _, _))
        .WillOnce(DoAll(InvokeMainLoopCB(), Return(0)))
        .WillOnce(DoAll(InvokeMainLoopCB(), Return(0)));

    string message_body_1, message_body_2;
    EXPECT_CALL(
        messaging_mock,
        mockSendPersistentMessage(false, _, _, "/api/v1/agents/events", _, _, MessageTypeTag::DEBUG)
    ).WillOnce(DoAll(SaveArg<1>(&message_body_1), Return(Maybe<string>(string(""))))).WillOnce(
        DoAll(SaveArg<1>(&message_body_2), Return(Maybe<string>(string(""))))
    );

    doFWError();
    line1 = line;
    doFWWarning();

    string expected_message_1 =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"Debug message\",\n"
        "        \"eventSeverity\": \"High\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Code Related\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"error\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingFunction\": \"doFWError\",\n"
        "            \"issuingFile\": \"debug_ut.cc\",\n"
        "            \"issuingLine\": " + line1 + ",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"eventMessage\": \"FW error message\"\n"
        "        }\n"
        "    }\n"
        "}";

    string expected_message_2 =
        "{\n"
        "    \"log\": {\n"
        "        \"eventTime\": \"2016-11-13T17:31:24.087\",\n"
        "        \"eventName\": \"Debug message\",\n"
        "        \"eventSeverity\": \"Medium\",\n"
        "        \"eventPriority\": \"Low\",\n"
        "        \"eventType\": \"Code Related\",\n"
        "        \"eventLevel\": \"Log\",\n"
        "        \"eventLogLevel\": \"warning\",\n"
        "        \"eventAudience\": \"Internal\",\n"
        "        \"eventAudienceTeam\": \"\",\n"
        "        \"eventFrequency\": 0,\n"
        "        \"eventTags\": [\n"
        "            \"Informational\"\n"
        "        ],\n"
        "        \"eventSource\": {\n"
        "            \"agentId\": \"Unknown\",\n"
        "            \"issuingFunction\": \"doFWWarning\",\n"
        "            \"issuingFile\": \"debug_ut.cc\",\n"
        "            \"issuingLine\": " + line + ",\n"
        "            \"eventTraceId\": \"\",\n"
        "            \"eventSpanId\": \"\",\n"
        "            \"issuingEngineVersion\": \"\",\n"
        "            \"serviceName\": \"Unnamed Nano Service\"\n"
        "        },\n"
        "        \"eventData\": {\n"
        "            \"eventMessage\": \"FW warning message\"\n"
        "        }\n"
        "    }\n"
        "}";

    EXPECT_EQ(message_body_1, expected_message_1);
    EXPECT_EQ(message_body_2, expected_message_2);

    EXPECT_CALL(mock_mainloop, doesRoutineExist(0)).WillOnce(Return(true));
    EXPECT_CALL(mock_mainloop, stop(0));
    Debug::fini();
}
