#include "time_print.h"
#include "cptest.h"

using namespace std;
using namespace testing;

TEST(time_printTest, time_print_operator_for_microseconds)
{
    chrono::microseconds usec(1000);
    stringstream buf;
    buf << usec;
    EXPECT_EQ(buf.str(), "1000usec");
}

TEST(time_printTest, time_print_operator_for_milliseconds)
{
    chrono::milliseconds ms(1000);
    stringstream buf;
    buf << ms;
    EXPECT_EQ(buf.str(), "1000ms");
}

TEST(time_printTest, time_print_operator_for_seconds)
{
    chrono::seconds sec(1000);
    stringstream buf;
    buf << sec;
    EXPECT_EQ(buf.str(), "1000s");
}

TEST(time_printTest, time_print_operator_for_minutes)
{
    chrono::minutes m(1000);
    stringstream buf;
    buf << m;
    EXPECT_EQ(buf.str(), "1000m");
}

TEST(time_printTest, time_print_operator_for_hours)
{
    chrono::hours hours_val(1000);
    stringstream buf;
    buf << hours_val;
    EXPECT_EQ(buf.str(), "1000h");
}
