#include "enum_array.h"

#include "cptest.h"

#include <vector>
using namespace std;

enum class Test1 { val1, val2, val3, val4, COUNT };

TEST(enum_array, enum_with_count)
{
    EnumArray<Test1, int> arr(0, 1, 2, 4);
    EXPECT_EQ(arr[Test1::val1], 0);
    EXPECT_EQ(arr[Test1::val2], 1);
    EXPECT_EQ(arr[Test1::val3], 2);
    EXPECT_EQ(arr[Test1::val4], 4);

    arr[Test1::val4] = 3;
    EXPECT_EQ(arr[Test1::val4], 3);

    vector<int> vals;
    for (auto num : arr) {
        vals.push_back(num);
    }
    vector<int> expected = { 0, 1, 2, 3 };
    EXPECT_EQ(vals, expected);
}

TEST(enum_array, auto_fill)
{
    EnumArray<Test1, int> arr(EnumArray<Test1, int>::Fill(), 18);

    vector<int> vals;
    for (auto num : arr) {
        vals.push_back(num);
    }
    vector<int> expected = { 18, 18, 18, 18 };
    EXPECT_EQ(vals, expected);
}

enum class Test2 { val1, val2, val3, val4 };
template <>
class EnumCount<Test2> : public EnumCountSpecialization<Test2, 4>
{
};

TEST(enum_array, enum_with_template_specialization)
{
    EnumArray<Test2, int> arr(0, 1, 2, 4);
    EXPECT_EQ(arr[Test2::val1], 0);
    EXPECT_EQ(arr[Test2::val2], 1);
    EXPECT_EQ(arr[Test2::val3], 2);
    EXPECT_EQ(arr[Test2::val4], 4);

    arr[Test2::val4] = 3;
    EXPECT_EQ(arr[Test2::val4], 3);

    vector<int> vals;
    for (auto num : arr) {
        vals.push_back(num);
    }
    vector<int> expected = { 0, 1, 2, 3 };
    EXPECT_EQ(vals, expected);
}

enum class Test3 { val1, val2, val3, val4 };

TEST(enum_array, array_with_explicit_length)
{
    EnumArray<Test3, int, 4> arr(0, 1, 2, 4);
    EXPECT_EQ(arr[Test3::val1], 0);
    EXPECT_EQ(arr[Test3::val2], 1);
    EXPECT_EQ(arr[Test3::val3], 2);
    EXPECT_EQ(arr[Test3::val4], 4);

    arr[Test3::val4] = 3;
    EXPECT_EQ(arr[Test3::val4], 3);

    vector<int> vals;
    for (auto num : arr) {
        vals.push_back(num);
    }
    vector<int> expected = { 0, 1, 2, 3 };
    EXPECT_EQ(vals, expected);
}
