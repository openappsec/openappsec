#include "cpu.h"

#include "mock/mock_cpu.h"
#include "cptest.h"
#include "cptest.h"
#include "config.h"
#include "config_component.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "environment.h"
#include "event.h"
#include "listener.h"

using namespace std;
using namespace testing;
using namespace chrono;

USE_DEBUG_FLAG(D_FW);
USE_DEBUG_FLAG(D_CONFIG);

string line = "";

void doFWError() { dbgError(D_FW) << "FW error message"; line = to_string(__LINE__); }
void doFWWarning() { dbgWarning(D_FW) << "FW warning message"; line = to_string(__LINE__); }
void doFWInfo() { dbgInfo(D_FW) << "FW info message"; line = to_string(__LINE__); }
void doFWDebug() { dbgDebug(D_FW) << "FW debug message"; line = to_string(__LINE__); }
void doFWTrace() { dbgTrace(D_FW) << "FW trace message"; line = to_string(__LINE__); }

class TestEnd {};

static ostream & operator<<(ostream &os, const Context::Error &) { return os; }

class CPUTest : public Test
{
public:
    CPUTest()
    {
        env.preload();
        env.init();
        i_env = Singleton::Consume<I_Environment>::from(env);
        i_env->registerValue<bool>("Is Orchestrator", true);
        EXPECT_CALL(mock_ml, getCurrentRoutineId()).WillRepeatedly(Return(5));
    }

    ~CPUTest() { Debug::setNewDefaultStdout(&cout); }

    StrictMock<MockMainLoop> mock_ml;
    StrictMock<MockTimeGet> mock_time;
    I_Environment *i_env;

private:
    ConfigComponent conf;
    ::Environment env;
};

class FailopenModeListener : public Listener<FailopenModeEvent>
{
public:
    void
    upon(const FailopenModeEvent &event) override
    {
        current_failopen_status = event.getFailopenMode();
    }

    bool
    isFailopenMode() const
    {
        return current_failopen_status;
    }

private:
    bool current_failopen_status = false;
};

TEST_F(CPUTest, basicTest)
{
    seconds time = seconds(0);

    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::ERROR);
    Debug::setUnitTestFlag(D_CONFIG, Debug::DebugLevel::ERROR);

    FailopenModeListener failopen_mode_listener;
    failopen_mode_listener.registerListener();

    EXPECT_CALL(mock_time, getMonotonicTime()).WillRepeatedly(Return(microseconds(time+=seconds(1))));
    EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(microseconds(1)));
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));

    I_MainLoop::Routine cpu_routine = nullptr;
    I_MainLoop::Routine debug_routine = nullptr;

    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::Timer, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&cpu_routine), Return(0)));

    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&debug_routine), Return(0)));

    EXPECT_CALL(
        mock_ml,
        addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::microseconds(600000000),
            _,
            _,
            _
        )
    ).WillRepeatedly(Return(1));

    StrictMock<MockCPU> mock_cpu;
    CPUManager cpu;
    cpu.init();

    doFWInfo();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message"));
    debug_output.str("");

    EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
    EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillRepeatedly(Invoke(
        [&] (chrono::microseconds duration) {
            EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(5)).count());
            static int count = 0;
            count++;
            if (count <= 5) {
                //Getting 90% CPU for 30 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
            }
            if (count > 5 && count <= 11) {
                //Getting 50% CPU for 30 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(50));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(50));
                EXPECT_TRUE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(true));
                EXPECT_TRUE(failopen_mode_listener.isFailopenMode());
            }
            if (count == 12) {
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
                throw TestEnd();
            }
        }
    ));

    try {
        cpu_routine();
    } catch(const TestEnd &T) {
        //During Failopen mode debugs will be ON
        EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
            .WillOnce(
                Invoke(
                    [&] (chrono::microseconds duration)
                    {
                        EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(30)).count());
                        debug_output.str("");
                        doFWError();
                        EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
                        debug_output.str("");

                        doFWInfo();
                        EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
                        debug_output.str("");

                        doFWWarning();
                        EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
                        debug_output.str("");

                        doFWDebug();
                        EXPECT_THAT(debug_output.str(), HasSubstr("@@@] FW debug message\n"));
                        debug_output.str("");

                        doFWTrace();
                        EXPECT_THAT(debug_output.str(), HasSubstr(">>>] FW trace message\n"));
                        debug_output.str("");
                    }
                )
            );
        debug_routine();
    }

    //Exiting Failopen mode - debugs will be back to pervious state
    doFWInfo();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
    debug_output.str("");

    failopen_mode_listener.unregisterListener();
    Debug::fini();
}

TEST_F(CPUTest, noDebugTest)
{
    seconds time = seconds(0);

    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::INFO);

    FailopenModeListener failopen_mode_listener;
    failopen_mode_listener.registerListener();

    EXPECT_CALL(mock_time, getMonotonicTime()).WillRepeatedly(Return(microseconds(time+=seconds(1))));
    EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(microseconds(1)));
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));

    I_MainLoop::Routine cpu_routine = nullptr;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::Timer, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&cpu_routine), Return(0)));

    EXPECT_CALL(
        mock_ml,
        addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::microseconds(600000000),
            _,
            _,
            _
        )
    ).WillRepeatedly(Return(1));

    StrictMock<MockCPU> mock_cpu;
    CPUManager cpu;
    cpu.preload();
    setConfiguration<uint>(0, string("CPU"), string("debug period"));
    cpu.init();

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));

    debug_output.str("");
    doFWInfo();
    EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
    EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillRepeatedly(Invoke(
        [&] (chrono::microseconds duration) {
            EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(5)).count());
            static int count = 0;
            count++;
            if (count <= 5) {
                //Getting 90% CPU for 30 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
            }
            if (count > 5 && count <= 11) {
                //Getting 50% CPU for 30 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(50));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(50));
                EXPECT_TRUE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(true));
                EXPECT_TRUE(failopen_mode_listener.isFailopenMode());
            }
            if (count == 12) {
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
                throw TestEnd();
            }
        }
    ));

    try {
        cpu_routine();
    } catch(const TestEnd &T) {}

    EXPECT_THAT(
        debug_output.str(),
        HasSubstr("Failopen mode is ON, CPU usage is above 85% for 30 seconds")
    );

    EXPECT_THAT(
        debug_output.str(),
        HasSubstr("Debug period for Failopen mode is zero seconds")
    );

    EXPECT_THAT(
        debug_output.str(),
        HasSubstr("Failopen mode is OFF, CPU usage is below 60% for 30 seconds")
    );

    debug_output.str("");
    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
    debug_output.str("");

    doFWInfo();
    EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    failopen_mode_listener.unregisterListener();
    Debug::fini();
}

TEST_F(CPUTest, CPUCalculatorConstructor)
{
    seconds time = seconds(0);
    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::INFO);

    EXPECT_CALL(mock_time, getMonotonicTime()).WillRepeatedly(Return(microseconds(time+=seconds(1))));
    EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(microseconds(1)));
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));
    I_MainLoop::Routine cpu_routine = nullptr;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::Timer, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&cpu_routine), Return(0)));

    EXPECT_CALL(
        mock_ml,
        addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::microseconds(600000000),
            _,
            _,
            _
        )
    ).WillRepeatedly(Return(1));

    CPUCalculator cpu_calc;
    CPUManager cpu;
    cpu.preload();
    cpu_calc.init();
    cpu.init();

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));

    debug_output.str("");
    doFWInfo();
    EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    cpu_calc.fini();
}

TEST_F(CPUTest, TwoFailopenDebugTest)
{
    seconds time = seconds(0);

    Debug::init();
    stringstream debug_output;
    Debug::setNewDefaultStdout(&debug_output);
    Debug::setUnitTestFlag(D_FW, Debug::DebugLevel::ERROR);

    FailopenModeListener failopen_mode_listener;
    failopen_mode_listener.registerListener();

    EXPECT_CALL(mock_time, getMonotonicTime()).WillRepeatedly(Return(microseconds(time+=seconds(1))));
    EXPECT_CALL(mock_time, getWalltime()).WillRepeatedly(Return(microseconds(1)));
    EXPECT_CALL(mock_time, getWalltimeStr()).WillRepeatedly(Return(string("2016-11-13T17:31:24.087")));

    I_MainLoop::Routine cpu_routine = nullptr;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::Timer, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&cpu_routine), Return(0)));

    I_MainLoop::Routine first_debug_routine = nullptr;
    I_MainLoop::Routine second_debug_routine = nullptr;
    EXPECT_CALL(mock_ml, addOneTimeRoutine(I_MainLoop::RoutineType::System, _, _, _))
        .WillOnce(DoAll(SaveArg<1>(&first_debug_routine), Return(0)))
        .WillOnce(DoAll(SaveArg<1>(&second_debug_routine), Return(0)));

    EXPECT_CALL(
        mock_ml,
        addRecurringRoutine(
            I_MainLoop::RoutineType::System,
            chrono::microseconds(600000000),
            _,
            _,
            _
        )
    ).WillRepeatedly(Return(1));

    StrictMock<MockCPU> mock_cpu;
    CPUManager cpu;
    setConfiguration<uint>(90, string("CPU"), string("debug period"));
    setConfiguration<uint>(25, "CPU", "watermark period");
    cpu.init();

    doFWInfo();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
    debug_output.str("");

    EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
    EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));

    EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>())).WillRepeatedly(Invoke(
        [&] (chrono::microseconds duration) {
            EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(5)).count());
            static int count = 0;
            count++;
            if (count <= 4) {
                //Getting 90% CPU for 5 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
            }
            if (count > 4 && count <= 9) {
                //Getting 50% CPU for 5 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(50));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(50));
                EXPECT_TRUE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(true));
                EXPECT_TRUE(failopen_mode_listener.isFailopenMode());
            }
            if (count > 9 && count <= 14) {
                //Getting 90% CPU for 5 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(90));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(90));
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
            }
            if (count > 14 && count <= 19) {
                //Getting 50% CPU for 5 seconds
                EXPECT_CALL(mock_cpu, getCurrentProcessCPUUsage()).WillOnce(Return(50));
                EXPECT_CALL(mock_cpu, getCurrentGeneralCPUUsage()).WillOnce(Return(50));
                EXPECT_TRUE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(true));
                EXPECT_TRUE(failopen_mode_listener.isFailopenMode());
            }
            if (count == 20) {
                EXPECT_FALSE(cpu.isFailOpenMode());
                EXPECT_THAT(i_env->get<bool>("Failopen Status"), IsValue(false));
                EXPECT_FALSE(failopen_mode_listener.isFailopenMode());
                throw TestEnd();
            }
        }
    ));

    try {
        cpu_routine();
    } catch(const TestEnd &T) {
        //During Failopen mode debugs will be ON
        EXPECT_CALL(mock_ml, yield(A<chrono::microseconds>()))
            .WillOnce(
                Invoke(
                    [&] (chrono::microseconds duration)
                    {
                        EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(90)).count());
                        debug_output.str("");
                        doFWError();
                        EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
                        debug_output.str("");

                        doFWInfo();
                        EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
                        debug_output.str("");

                        doFWWarning();
                        EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
                        debug_output.str("");

                        doFWDebug();
                        EXPECT_THAT(debug_output.str(), HasSubstr("@@@] FW debug message\n"));
                        debug_output.str("");

                        doFWTrace();
                        EXPECT_THAT(debug_output.str(), HasSubstr(">>>] FW trace message\n"));
                        debug_output.str("");
                    }
                )
            )
            .WillOnce(
                Invoke(
                    [&] (chrono::microseconds duration)
                    {
                        EXPECT_EQ(duration.count(), chrono::microseconds(chrono::seconds(90)).count());
                        debug_output.str("");
                        doFWError();
                        EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
                        debug_output.str("");

                        doFWInfo();
                        EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
                        debug_output.str("");

                        doFWWarning();
                        EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
                        debug_output.str("");

                        doFWDebug();
                        EXPECT_THAT(debug_output.str(), HasSubstr("@@@] FW debug message\n"));
                        debug_output.str("");

                        doFWTrace();
                        EXPECT_THAT(debug_output.str(), HasSubstr(">>>] FW trace message\n"));
                        debug_output.str("");
                    }
                )
            );

        first_debug_routine();

        //Exiting first Failopen mode - debugs are still enabled as only second failopen end will turn them off
        debug_output.str("");
        doFWError();
        EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
        debug_output.str("");

        doFWInfo();
        EXPECT_THAT(debug_output.str(), HasSubstr("---] FW info message\n"));
        debug_output.str("");

        doFWWarning();
        EXPECT_THAT(debug_output.str(), HasSubstr("###] FW warning message\n"));
        debug_output.str("");

        doFWDebug();
        EXPECT_THAT(debug_output.str(), HasSubstr("@@@] FW debug message\n"));
        debug_output.str("");

        doFWTrace();
        EXPECT_THAT(debug_output.str(), HasSubstr(">>>] FW trace message\n"));
        debug_output.str("");

        second_debug_routine();
    }

    // Back to previous debug state
    doFWInfo();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWWarning();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWDebug();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWTrace();
    EXPECT_THAT(debug_output.str(), "");
    debug_output.str("");

    doFWError();
    EXPECT_THAT(debug_output.str(), HasSubstr("!!!] FW error message\n"));
    debug_output.str("");

    failopen_mode_listener.unregisterListener();
    Debug::fini();
}
