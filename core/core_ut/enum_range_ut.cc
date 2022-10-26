#include "enum_range.h"

#include "cptest.h"

#include <vector>
using namespace std;
using testing::ElementsAre;

enum class Test1 { val1, val2, val3, val4, COUNT };

TEST(enum_range, whole_range)
{
    EXPECT_THAT(NGEN::Range<Test1>(), ElementsAre(Test1::val1, Test1::val2, Test1::val3, Test1::val4));
    EXPECT_THAT(makeRange<Test1>(), ElementsAre(Test1::val1, Test1::val2, Test1::val3, Test1::val4));
}

TEST(enum_range, up_to_point)
{
    EXPECT_THAT(NGEN::Range<Test1>(Test1::val3), ElementsAre(Test1::val1, Test1::val2, Test1::val3));
    EXPECT_THAT(makeRange(Test1::val3), ElementsAre(Test1::val1, Test1::val2, Test1::val3));
}

TEST(enum_range, slice_range)
{
    EXPECT_THAT(NGEN::Range<Test1>(Test1::val2, Test1::val3), ElementsAre(Test1::val2, Test1::val3));
    EXPECT_THAT(makeRange(Test1::val2, Test1::val3), ElementsAre(Test1::val2, Test1::val3));
}


enum class Test2 { val1, val2, val3, val4 };
template <>
class EnumCount<Test2> : public EnumCountSpecialization<Test2, 4> {};

TEST(enum_range, whole_range_without_count_elem)
{
    EXPECT_THAT(NGEN::Range<Test2>(), ElementsAre(Test2::val1, Test2::val2, Test2::val3, Test2::val4));
    EXPECT_THAT(makeRange<Test2>(), ElementsAre(Test2::val1, Test2::val2, Test2::val3, Test2::val4));
}

TEST(enum_range, int_up_point)
{
    EXPECT_THAT(NGEN::Range<int>(9), ElementsAre(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
    EXPECT_THAT(makeRange(9), ElementsAre(0, 1, 2, 3, 4, 5, 6, 7, 8, 9));
}

TEST(enum_range, int_slice_range)
{
    EXPECT_THAT(NGEN::Range<int>(5, 10), ElementsAre(5, 6, 7, 8, 9, 10));
    EXPECT_THAT(makeRange(5, 10), ElementsAre(5, 6, 7, 8, 9, 10));
}
