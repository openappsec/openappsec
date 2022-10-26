#include <string>

#include "cptest.h"
#include "time_proxy.h"
#include "singleton.h"

using namespace std;
using namespace testing;
using namespace std::chrono;

class TimeProxyTest : public Test
{
public:
    TimeProxyComponent proxy;
    I_TimeGet *i_time_get = Singleton::Consume<I_TimeGet>::from(proxy);
    I_TimeSet *i_time_set = Singleton::Consume<I_TimeSet>::from(proxy);
};

TEST_F(TimeProxyTest, get_without_set)
{
    auto mono1 = i_time_get->getMonotonicTime(); // Check that it doesn't crash - but we can't verify the value.
    usleep(1000);
    auto mono2 = i_time_get->getMonotonicTime();
    EXPECT_LT(mono1, mono2);

    i_time_get->getWalltime(); // Check that it doesn't crash - but we can't verify the value.

    // Checking that ISO-8601 time format is used, e.g.: 2016-11-11T15:33:01.034
    EXPECT_THAT(
        i_time_get->getWalltimeStr(),
        MatchesRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}")
    );
    EXPECT_THAT(
        i_time_get->getLocalTimeStr(),
        MatchesRegex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}")
    );
}

TEST_F(TimeProxyTest, set)
{
    auto marty_mcfly_time = microseconds((1445455680L)*1000000); // 21 Oct 2015, 19:28
    std::string marty_mcfly_time_str = "2015-10-21T19:28:00.000000";
    i_time_set->setWalltime(marty_mcfly_time);
    EXPECT_EQ(i_time_get->getWalltime(), marty_mcfly_time);
    EXPECT_EQ(i_time_get->getWalltimeStr(),  marty_mcfly_time_str);

    i_time_set->setMonotonicTime(microseconds(0));
    auto time = i_time_get->getMonotonicTime();
    i_time_set->setMonotonicTime(microseconds(1337000));
    EXPECT_EQ(i_time_get->getMonotonicTime(), time + microseconds(1337000));
    usleep(1000);
    EXPECT_EQ(i_time_get->getMonotonicTime(), time + microseconds(1337000));

    // No problem reseting walltime to whatever
    i_time_set->setWalltime(microseconds(1000000));
    i_time_set->setWalltime(microseconds(2001000));
    EXPECT_EQ(i_time_get->getWalltime(), microseconds(2001000));
    EXPECT_EQ(i_time_get->getWalltimeStr(), "1970-01-01T00:00:02.001000");

    // You can move monotonic time forwards
    i_time_set->setMonotonicTime(microseconds(2000000));
    EXPECT_EQ(i_time_get->getMonotonicTime(), time + microseconds(2000000));

    // But not backwards
    cptestPrepareToDie();
    EXPECT_DEATH(i_time_set->setMonotonicTime(microseconds(1000)), "Monotonic time must not go back!");
}
