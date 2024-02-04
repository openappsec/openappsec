#include "memory_consumption.h"
#include "../memory_metric.h"

#include "cptest.h"
#include "cptest.h"
#include "config_component.h"
#include "environment.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"
#include "config_component.h"
#include "debug.h"
#include <boost/regex.hpp>

using namespace std;
using namespace testing;

USE_DEBUG_FLAG(D_MONITORING);

class MemoryConsumptionTest : public Test
{
public:
    MemoryConsumptionTest()
    {
        env.preload();
        env.init();
        Singleton::Consume<I_Environment>::from(env)->registerValue<string>("Service Name", "Orchestration");

        EXPECT_CALL(mock_ml, addRecurringRoutine(_, _, _, _, _)).WillRepeatedly(Return(0));

        EXPECT_CALL(mock_ml, addRecurringRoutine(I_MainLoop::RoutineType::Timer, _, _, _, _))
            .WillRepeatedly(DoAll(SaveArg<2>(&memory_routine), Return(1)));

        memory_consumption.preload();
        memory_consumption.init();
    }

    StrictMock<MockMainLoop> mock_ml;
    StrictMock<MockTimeGet>  mock_time;
    MemoryCalculator         memory_consumption;
    I_MainLoop::Routine      memory_routine = nullptr;

private:
    ConfigComponent conf;
    ::Environment   env;
};

TEST_F(MemoryConsumptionTest, initializeMemoryConsumption)
{
    memory_routine();
}

TEST_F(MemoryConsumptionTest, memoryConsumptionMetricTest)
{
    memory_routine();

    AllMetricEvent all_mt_event;
    all_mt_event.setReset(false);
    all_mt_event.notify();
    EXPECT_NE(all_mt_event.performNamedQuery().begin()->second, "");

    boost::regex expected_reg(
        "{\\n\\s*\\\"Metric\\\":\\s*\\\"Memory usage\\\",\\n"
        "\\s*\\\"Reporting interval\\\":\\s*600,\\n"
        "\\s*\\\"serviceVirtualMemorySizeMaxSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"serviceVirtualMemorySizeMinSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"serviceVirtualMemorySizeAvgSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"serviceRssMemorySizeMaxSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"serviceRssMemorySizeMinSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"serviceRssMemorySizeAvgSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"generalTotalMemorySizeMaxSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"generalTotalMemorySizeMinSample\\\":\\s*\\d*\\.\\d*,\\n"
        "\\s*\\\"generalTotalMemorySizeAvgSample\\\":\\s*\\d*\\.\\d*\\n}"
    );

    EXPECT_TRUE(boost::regex_search(all_mt_event.query()[0], expected_reg));
}
